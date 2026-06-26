#!/usr/bin/env python3
"""Render the CyberAI ASCII brand logo to PNG (matches internal/cli/brand.go)."""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

LOGO = """   ______      __              ___    ____
  / ____/_  __/ /_  ___  _____/   |  /  _/
 / /   / / / / __ \\/ _ \\/ ___/ /| |  / /  
/ /___/ /_/ / /_/ /  __/ /  / ___ |_/ /   
\\____/\\__, /_.___/\\___/_/  /_/  |_/___/   
     /____/"""

TAGLINE = "local security scanning, triage, and reports"
COLORS = ["#34d399", "#5eead4", "#8ce99a"]
BG = "#0b1220"
TAGLINE_COLOR = "#94a3b8"
FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
OUT = Path(__file__).resolve().parents[1] / "docs" / "assets" / "cyberai-logo.png"


def main() -> None:
    font_size = 18
    font = ImageFont.truetype(FONT_PATH, font_size)
    tag_font = ImageFont.truetype(FONT_PATH, 14)

    lines = LOGO.split("\n")
    pad_x, pad_y = 32, 28
    line_h = font_size + 6
    tag_gap = 18

    max_w = max(font.getlength(line) for line in lines)
    tag_w = tag_font.getlength(TAGLINE)
    width = int(max(max_w, tag_w) + pad_x * 2)
    height = int(pad_y * 2 + len(lines) * line_h + tag_gap + tag_font.size + 8)

    img = Image.new("RGBA", (width, height), BG + "ff")
    draw = ImageDraw.Draw(img)

    y = pad_y
    for i, line in enumerate(lines):
        color = COLORS[i % len(COLORS)]
        draw.text((pad_x, y), line, font=font, fill=color)
        y += line_h

    y += tag_gap
    draw.text((pad_x, y), TAGLINE, font=tag_font, fill=TAGLINE_COLOR)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    img.save(OUT, "PNG", optimize=True)
    print(f"wrote {OUT} ({width}x{height})")


if __name__ == "__main__":
    main()
