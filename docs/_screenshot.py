"""Regenerate docs/report-screenshot.png from the sample report.

Run after regenerating docs/sample-report.html:
    python docs/_screenshot.py
"""

from pathlib import Path

from playwright.sync_api import sync_playwright

DOCS = Path(__file__).parent

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1080, "height": 1180}, device_scale_factor=2)
    page.goto((DOCS / "sample-report.html").as_uri())
    page.screenshot(path=str(DOCS / "report-screenshot.png"))
    browser.close()
