"""
广西大学研究生综合管理系统 -> GitHub Actions 加密同步脚本
支持 AES-GCM 加密写入 schedule.json，防止公开仓库泄露课表隐私
"""
import base64
import json
import os
import re
from datetime import datetime
from pathlib import Path
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

GXU_YJS_URL = "https://yjsxt.gxu.edu.cn/tp/"
CACHE_FILE = Path(__file__).parent / "schedule.json"
COLORS = ["blue", "indigo", "emerald", "amber", "rose", "teal"]


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


def parse_schedule_html(html: str) -> list:
    soup = BeautifulSoup(html, "html.parser")
    courses = []
    cells = soup.select("td[data-day], td.kb-cell, .timetable-item, .course-item")
    idx = 0
    for cell in cells:
        text = cell.get_text(" | ", strip=True)
        if not text or len(text) < 2:
            continue
        day = int(cell.get("data-day") or 1)
        start_p = int(cell.get("data-start") or 1)
        end_p = int(cell.get("data-end") or start_p + 1)
        parts = [p.strip() for p in text.split("|") if p.strip()]
        name = parts[0]
        room = next((p for p in parts[1:] if any(k in p for k in ["楼", "室", "馆", "厅", "区"])), parts[1] if len(parts) > 1 else "待定教室")
        teacher = next((p for p in parts[1:] if "师" in p or (len(p) <= 4 and p != room)), "")
        week_match = re.search(r"(\d+-\d+(?:,\d+-\d+)*)", text)
        weeks = week_match.group(1) if week_match else "1-16"
        courses.append({
            "id": f"gxu_{day}_{start_p}_{idx}",
            "name": name,
            "room": room,
            "teacher": teacher,
            "day": day,
            "startPeriod": start_p,
            "endPeriod": end_p,
            "weeks": weeks,
            "color": COLORS[idx % len(COLORS)],
            "changeNote": ""
        })
        idx += 1
    return courses


def diff_courses(old_list: list, new_list: list) -> tuple[list, list]:
    old_map = {c["name"]: c for c in old_list}
    logs = []
    now_str = datetime.now().strftime("%m-%d %H:%M")
    for c in new_list:
        prev = old_map.get(c["name"])
        if not prev:
            c["changeNote"] = "新增课程"
            logs.append({"time": now_str, "message": f"新增课程：《{c['name']}》"})
        else:
            diffs = []
            if prev.get("room") != c.get("room"):
                diffs.append(f"教室由 {prev.get('room')} 改为 {c.get('room')}")
            if prev.get("day") != c.get("day") or prev.get("startPeriod") != c.get("startPeriod"):
                diffs.append(f"时间由周{prev.get('day')}第{prev.get('startPeriod')}-{prev.get('endPeriod')}节调至周{c.get('day')}第{c.get('startPeriod')}-{c.get('endPeriod')}节")
            if diffs:
                note = "；".join(diffs)
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


def fetch_from_gxu() -> list:
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
        page.goto(GXU_YJS_URL, timeout=60000)
        page.wait_for_load_state("networkidle")
        print(f"当前页面 URL: {page.url} | 标题: {page.title()}")

        if "ca.gxu.edu.cn" in page.url or "toLogin" in page.url or "login" in page.url.lower():
            user_input = page.locator("input[name='username']:visible, input#username:visible, input#un:visible, input[type='text']:visible").first
            pwd_input = page.locator("input[name='password']:visible, input#password:visible, input#pd:visible, input[type='password']:visible").first
            user_input.fill(username)
            pwd_input.fill(password)

            captcha_img = page.locator("img[src*='captcha']:visible, img[src*='code']:visible, img#captchaImg:visible, img#codeImg:visible").first
            captcha_input = page.locator("input[name='captcha']:visible, input#captcha:visible, input[placeholder*='验证码']:visible").first
            if captcha_img.count() > 0 and captcha_img.is_visible() and captcha_input.count() > 0 and captcha_input.is_visible():
                code = try_ocr_captcha(captcha_img.screenshot())
                print(f"识别到图形验证码: {code}")
                if code:
                    captcha_input.fill(code)
            else:
                print("当前登录页未显示图形验证码，直接提交账号密码。")

            login_btn = page.locator("button[type='submit']:visible, input[type='submit']:visible, .login-btn:visible, #loginBtn:visible, #index_login_btn:visible, a.login_btn:visible").first
            login_btn.click()
            page.wait_for_timeout(5000)
            page.wait_for_load_state("networkidle")
            print(f"登录后页面 URL: {page.url} | 标题: {page.title()}")

            if "ca.gxu.edu.cn" in page.url or "toLogin" in page.url:
                err_text = page.locator(".error, .err-msg, #errormsg, .alert-danger").all_inner_texts()
                raise RuntimeError(f"统一身份认证未通过，当前停留在 {page.url}，页面提示: {err_text}")

        # 尝试自动点击“课表”相关菜单
        kb_link = page.locator("a:has-text('课表'), span:has-text('课表'), li:has-text('我的课表')").first
        if kb_link.count() > 0 and kb_link.is_visible():
            print("找到课表菜单，正在点击进入...")
            kb_link.click()
            page.wait_for_timeout(3000)
            page.wait_for_load_state("networkidle")

        # 收集主页面和所有 iframe 的 HTML 进行解析
        all_html = [page.content()]
        for frame in page.frames:
            try:
                all_html.append(frame.content())
            except Exception:
                pass

        courses = []
        for h in all_html:
            parsed = parse_schedule_html(h)
            if parsed:
                courses.extend(parsed)

        if not courses:
            links = [a.inner_text().strip() for a in page.locator("a:visible").all()[:25]]
            print("未检测到课表元素，当前页面可见链接示例:", [x for x in links if x])

        browser.close()
        return courses


if __name__ == "__main__":
    view_password = os.getenv("VIEW_PASSWORD", "").strip()
    old_courses, old_logs = [], []
    if CACHE_FILE.exists():
        try:
            old_data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            if old_data.get("encrypted") and view_password:
                old_data = decrypt_payload(old_data, view_password)
            old_courses = old_data.get("courses", [])
            old_logs = old_data.get("change_logs", [])
        except Exception:
            pass

    new_courses = fetch_from_gxu()
    if not new_courses:
        print("登录成功，但暂未在当前页面解析到课表元素，请查看上方打印的页面 URL 和链接列表。")
    else:
        merged, new_logs = diff_courses(old_courses, new_courses)
        payload = {
            "term_start": os.getenv("TERM_START", "2026-09-07"),
            "updated_at": datetime.utcnow().isoformat() + "Z",
            "courses": merged,
            "change_logs": (new_logs + old_logs)[:20]
        }
        output_obj = encrypt_payload(payload, view_password) if view_password else payload
        CACHE_FILE.write_text(json.dumps(output_obj, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"成功更新 {len(merged)} 门课程（{'已加密' if view_password else '未加密'}）！")
EOF
