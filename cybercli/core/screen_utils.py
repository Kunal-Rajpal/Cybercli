# cybercli/core/screen_utils.py
from pathlib import Path
import subprocess, shutil, time
from typing import Optional

def take_screenshot_playwright(url: str, out_png: Path, timeout:int=20) -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return False
    try:
        out_png.parent.mkdir(parents=True, exist_ok=True)
        with sync_playwright() as p:
            browser = p.chromium.launch(args=['--no-sandbox', '--disable-setuid-sandbox'], headless=True)
            page = browser.new_page(viewport={"width":1366,"height":768})
            page.goto(url, wait_until="networkidle", timeout=timeout*1000)
            page.screenshot(path=str(out_png), full_page=True)
            browser.close()
        return True
    except Exception:
        return False

def take_screenshot_selenium(url: str, out_png: Path, timeout:int=20) -> bool:
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options as ChromeOptions
    except Exception:
        return False
    try:
        opts = ChromeOptions()
        opts.add_argument("--headless=new")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--window-size=1600,1000")
        out_png.parent.mkdir(parents=True, exist_ok=True)
        driver = webdriver.Chrome(options=opts)
        driver.set_page_load_timeout(timeout)
        driver.get(url)
        time.sleep(1.2)
        driver.save_screenshot(str(out_png))
        driver.quit()
        return True
    except Exception:
        return False

def take_screenshot_wkhtml(url: str, out_png: Path) -> bool:
    if shutil.which("wkhtmltoimage"):
        try:
            out_png.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["wkhtmltoimage", url, str(out_png)], timeout=60)
            return out_png.exists()
        except Exception:
            return False
    return False

