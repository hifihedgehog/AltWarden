"""Draws the README header, the social preview and the two images on the Discord app page.

Each one comes from the logo in altwarden/web/static/img/logo.svg, so a change to the logo or the
tagline only needs this script run again. It needs Playwright and Microsoft Edge:

    python scripts/build_art.py
"""
from __future__ import annotations

import re
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
LOGO = (ROOT / "altwarden/web/static/img/logo.svg").read_text(encoding="utf-8")
GATE_PATHS = (
    '<path d="M112 424V240c0-79.5 64.5-144 144-144s144 64.5 144 144v184H360V244c0-57.4-46.6-104-104-104s-104 46.6-104 104v180z"/>'
    '<circle cx="256" cy="238" r="50"/><path d="M232 276h48l26 148h-100z"/>'
)
TAGLINE = "Discord verification with no readable IPs or emails"
PAGE = """<!doctype html><meta charset="utf-8"><style>
* {{ margin: 0; box-sizing: border-box; }}
html, body {{ width: {width}px; height: {height}px; overflow: hidden; }}
body {{ position: relative; background: linear-gradient(90deg, #0b1219, #102930); font-family: "Segoe UI", system-ui, sans-serif; }}
.logo, .name, .line, .gate {{ position: absolute; }}
.logo svg, .gate svg {{ display: block; width: 100%; height: 100%; }}
.name {{ color: #eef2f7; font-weight: 700; line-height: 1; letter-spacing: -.01em; white-space: nowrap; }}
.line {{ color: #9fb0bc; line-height: 1; white-space: nowrap; }}
{style}
</style>{body}"""


def logo() -> str:
    return f'<div class="logo">{LOGO}</div>'


def gate() -> str:
    return f'<div class="gate"><svg viewBox="96 80 320 360" fill="#2dd4bf">{GATE_PATHS}</svg></div>'


def words(line: str = TAGLINE) -> str:
    return f'<div class="name">AltWarden</div><div class="line">{line}</div>'


ART = {
    "header.png": (1280, 320, logo() + words(), """
        .logo { left: 80px; top: 80px; width: 160px; height: 160px; }
        .name { left: 268px; top: 104px; font-size: 76px; }
        .line { left: 270px; top: 190px; font-size: 30px; }"""),
    "social-preview.png": (1280, 640, logo() + words(), """
        .logo { left: 90px; top: 160px; width: 320px; height: 320px; }
        .name { left: 466px; top: 234px; font-size: 92px; }
        .line { left: 470px; top: 344px; font-size: 32px; }"""),
    # Discord lays the bot's picture over the lower left of its banner, so the words start to the right of it.
    "discord-banner.png": (680, 240, gate() + words("Verification with no readable IPs or emails"), """
        .gate { right: -36px; top: 22px; width: 300px; height: 338px; opacity: .13; }
        .name { left: 232px; top: 66px; font-size: 66px; }
        .line { left: 235px; top: 142px; font-size: 21.5px; }"""),
    "discord-cover.png": (1024, 576, logo() + words(), """
        .logo { left: 412px; top: 92px; width: 200px; height: 200px; }
        .name { left: 0; width: 1024px; text-align: center; top: 322px; font-size: 88px; }
        .line { left: 0; width: 1024px; text-align: center; top: 432px; font-size: 34px; }"""),
}


def main() -> None:
    target = ROOT / "assets"
    target.mkdir(exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="msedge", headless=True)
        for name, (width, height, body, style) in ART.items():
            page = browser.new_page(viewport={"width": width, "height": height}, device_scale_factor=1)
            page.set_content(PAGE.format(width=width, height=height, style=re.sub(r"\s+", " ", style), body=body))
            page.evaluate("document.fonts.ready")
            page.screenshot(path=target / name, omit_background=False)
            page.close()
            print(f"{name}: {width}x{height}")
        browser.close()


if __name__ == "__main__":
    main()
