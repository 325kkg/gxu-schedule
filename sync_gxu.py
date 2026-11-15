"""
广西大学研究生综合管理系统 -> GitHub Actions 加密同步脚本
直接对接 yjsxt.gxu.edu.cn/tp/ 的课表接口，精准解析每周课表、教师、教室与调停课记录
"""
import base64
import json
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

GXU_KB_URL = "https://yjsxt.gxu.edu.cn/tp/view?m=up#act=yjs/py/pkgl/ckkbOfYjs"
CACHE_FILE = Path(__file__).parent / "schedule.json"
COLORS = ["blue", "indigo", "emerald", "amber", "rose", "teal"]
DAY_MAP = {"一": 1, "二": 2, "三": 3, "四": 4, "五": 5, "六": 6, "日": 7, "天": 7}


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_payload(payload: dict, password: str) -> dict:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return {
        "encrypted": True,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "updated_at": payload.get("updated_at", "")
    }


def decrypt_payload(enc_obj: dict, password: str) -> dict:
    salt = base64.b64decode(enc_obj["salt"])
    nonce = base64.b64decode(enc_obj["nonce"])
    ciphertext = base64.b64decode(enc_obj["ciphertext"])
    key = derive_key(password, salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))


def parse_sksjdd_records(records: list) -> tuple[list, int]:
    """
    解析广西大学研究生系统课程列表（来自 #xsDataTable 或 findXkmdByXsPage 接口）。
    每条记录包含课程名 kcmc、任课教师 rkjs/pkjs、上课时间地点 sksjdd。
    """
    courses = []
    max_week = 19
    color_map = {}
    color_idx = 0

    pattern = re.compile(
        r"第([0-9\-、,，]+?)周\s+星期([一二三四五六日天])\s+第(\d+)(?:-(\d+))?节\s+(\S+)\s+([^;；\s]+)"
    )

    for item in records:
        name = (item.get("kcmc") or "").strip()
        if not name:
            continue
        if name not in color_map:
            color_map[name] = COLORS[color_idx % len(COLORS)]
            color_idx += 1
        color = color_map[name]
        fallback_teacher = (item.get("pkjs") or item.get("rkjs") or "").strip()
        sksjdd = (item.get("sksjdd") or "").strip()

        matches = list(pattern.finditer(sksjdd))
        for m_idx, m in enumerate(matches):
            raw_weeks, day_ch, sp_str, ep_str, room, teacher = m.groups()
            weeks_clean = raw_weeks.replace("、", ",").replace("，", ",")
            for num in re.findall(r"\d+", weeks_clean):
                max_week = max(max_week, int(num))
            day = DAY_MAP.get(day_ch, 1)
            sp = max(1, min(13, int(sp_str)))
            ep = max(sp, min(13, int(ep_str or sp_str)))
            courses.append({
                "id": f"gxu_{day}_{sp}_{len(courses)}_{m_idx}",
                "name": name,
                "room": room.strip(),
                "teacher": (teacher or fallback_teacher).strip(),
                "day": day,
                "startPeriod": sp,
                "endPeriod": ep,
                "weeks": weeks_clean,
                "color": color,
                "changeNote": ""
            })

    return courses, max_week


def parse_xs_table_from_html(html: str) -> tuple[list, int]:
    soup = BeautifulSoup(html, "html.parser")
    table = soup.select_one("#xsDataTable")
    if not table:
        return [], 19
    records = []
    for tr in table.select("tbody tr"):
        tds = tr.find_all("td")
        if len(tds) < 7:
            continue
        kcmc = tds[2].get_text(strip=True).replace("课程名称：", "")
        sksjdd = tds[5].get_text(strip=True).replace("上课时间、地点：", "")
        rkjs = tds[6].get_text(strip=True).replace("任课教师：", "")
        records.append({"kcmc": kcmc, "sksjdd": sksjdd, "rkjs": rkjs})
    return parse_sksjdd_records(records)


def diff_courses(old_list: list, new_list: list, official_ttk: list) -> tuple[list, list]:
    old_sig = {f"{c['name']}|{c['day']}|{c['startPeriod']}|{c['weeks']}": c for c in old_list}
    logs = []
    now_str = datetime.now().strftime("%m-%d %H:%M")

    # 1. 纳入官方调停课记录
    ttk_names = {}
    for t in official_ttk:
        kcmc = (t.get("kcmc") or "").strip()
        msg = f"{t.get('sqlxmc', '调课')}：原[{t.get('ysksjdd', '')}] → 现[{t.get('tzhsksjdd', '')}]"
        if kcmc:
            ttk_names[kcmc] = msg
            logs.append({"time": "官方调停课", "message": f"《{kcmc}》{msg}"})

    # 2. 对比本地历史变动
    for c in new_list:
        if c["name"] in ttk_names:
            c["changeNote"] = ttk_names[c["name"]]
            continue
        sig = f"{c['name']}|{c['day']}|{c['startPeriod']}|{c['weeks']}"
        prev = old_sig.get(sig)
        if old_list and not prev:
            c["changeNote"] = "课程时间或周次有更新"
            logs.append({"time": now_str, "message": f"《{c['name']}》周{c['day']}第{c['startPeriod']}-{c['endPeriod']}节（第{c['weeks']}周）有更新"})
        elif prev and prev.get("room") != c.get("room"):
            note = f"教室由 {prev.get('room')} 改为 {c.get('room')}"
            c["changeNote"] = note
            logs.append({"time": now_str, "message": f"《{c['name']}》{note}"})

    return new_list, logs


def try_ocr_captcha(img_bytes: bytes) -> str:
    try:
        import ddddocr
        ocr = ddddocr.DdddOcr(show_ad=False)
        return ocr.classification(img_bytes)
    except Exception:
        return ""


def fetch_from_gxu() -> tuple[list, list, str, int]:
    username = os.getenv("GXU_USERNAME", "").strip()
    password = os.getenv("GXU_PASSWORD", "").strip()
    cookie_str = os.getenv("GXU_COOKIE", "").strip()

    if not username or not password:
        raise RuntimeError("未检测到 GXU_USERNAME 或 GXU_PASSWORD，请在仓库 Settings -> Secrets 中配置。")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        if cookie_str:
            cookies = []
            for pair in cookie_str.split(";"):
                if "=" in pair:
                    k, v = pair.strip().split("=", 1)
                    cookies.append({"name": k, "value": v, "domain": ".gxu.edu.cn", "path": "/"})
            if cookies:
                context.add_cookies(cookies)

        page = context.new_page()
        page.goto(GXU_KB_URL, timeout=60000)
        page.wait_for_load_state("networkidle")

        if "ca.gxu.edu.cn" in page.url or "toLogin" in page.url or "login" in page.url.lower():
            user_input = page.locator("input[name='username']:visible, input#username:visible, input#un:visible, input[type='text']:visible").first
            pwd_input = page.locator("input[name='password']:visible, input#password:visible, input#pd:visible, input[type='password']:visible").first
            user_input.fill(username)
            pwd_input.fill(password)

            captcha_img = page.locator("img[src*='captcha']:visible, img[src*='code']:visible, img#captchaImg:visible, img#codeImg:visible").first
            captcha_input = page.locator("input[name='captcha']:visible, input#captcha:visible, input[placeholder*='验证码']:visible").first
            if captcha_img.count() > 0 and captcha_img.is_visible() and captcha_input.count() > 0 and captcha_input.is_visible():
                code = try_ocr_captcha(captcha_img.screenshot())
                if code:
                    captcha_input.fill(code)

            page.locator("button[type='submit']:visible, input[type='submit']:visible, .login-btn:visible, #loginBtn:visible, #index_login_btn:visible, a.login_btn:visible").first.click()
            page.wait_for_timeout(4000)
            page.wait_for_load_state("networkidle")

            if "ca.gxu.edu.cn" in page.url or "toLogin" in page.url:
                raise RuntimeError(f"统一身份认证未通过，当前停留在 {page.url}")

        # 跳转到我的课表页面并等待表格数据加载完成
        if "ckkbOfYjs" not in page.url:
            page.goto(GXU_KB_URL, timeout=60000)
            page.wait_for_load_state("networkidle")
        page.wait_for_timeout(3000)

        # 通过页面同源接口获取当前教学周次与官方调停课记录
        term_start = os.getenv("TERM_START", "2026-09-07")
        today = datetime.now().date()
        monday = today - timedelta(days=today.weekday())
        sunday = monday + timedelta(days=6)
        zkb_res = page.evaluate("""async ({ksrq, jsrq}) => {
            try {
                const body = new URLSearchParams({type: '2', ksrq, jsrq});
                const r = await fetch('/tp/yjs/py/pkgl/findZkb2', {method: 'POST', body});
                return await r.json();
            } catch (e) { return {}; }
        }""", {"ksrq": monday.isoformat(), "jsrq": sunday.isoformat()})
        if zkb_res and str(zkb_res.get("msg", "")).isdigit():
            cur_wk = int(zkb_res["msg"])
            term_start = (monday - timedelta(weeks=cur_wk - 1)).isoformat()
            print(f"官方校历校准成功：本周为第 {cur_wk} 周，第1周周一={term_start}")

        ttk_res = page.evaluate("""async () => {
            try {
                const body = new URLSearchParams({draw: '1', start: '0', length: '50'});
                const r = await fetch('/tp/yjs/py/pkgl/findListByXhPage', {method: 'POST', body});
                return await r.json();
            } catch (e) { return {data: []}; }
        }""")
        official_ttk = ttk_res.get("data") or ttk_res.get("list") or []

        # 优先从页面已渲染的 #xsDataTable 解析全部课程（含精确周次、星期、节次、教室、教师）
        courses, max_week = parse_xs_table_from_html(page.content())
        if not courses:
            for frame in page.frames:
                try:
                    c, mw = parse_xs_table_from_html(frame.content())
                    if c:
                        courses, max_week = c, mw
                        break
                except Exception:
                    pass

        browser.close()
        return courses, official_ttk, term_start, max_week


if __name__ == "__main__":
    view_password = os.getenv("VIEW_PASSWORD", "").strip()
    old_courses = []
    if CACHE_FILE.exists():
        try:
            old_data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            if old_data.get("encrypted") and view_password:
                old_data = decrypt_payload(old_data, view_password)
            old_courses = old_data.get("courses", [])
        except Exception:
            pass

    new_courses, official_ttk, term_start, max_week = fetch_from_gxu()
    if not new_courses:
        raise RuntimeError("未能从官网课表页解析到课程数据。")

    merged, new_logs = diff_courses(old_courses, new_courses, official_ttk)
    payload = {
        "term_start": term_start,
        "total_weeks": max(19, max_week),
        "updated_at": datetime.utcnow().isoformat() + "Z",
        "courses": merged,
        "change_logs": new_logs[:20]
    }
    output_obj = encrypt_payload(payload, view_password) if view_password else payload
    CACHE_FILE.write_text(json.dumps(output_obj, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"成功解析 {len(merged)} 条排课记录（学期共 {payload['total_weeks']} 周，开学周一 {term_start}，{'已加密' if view_password else '未加密'}）！")
