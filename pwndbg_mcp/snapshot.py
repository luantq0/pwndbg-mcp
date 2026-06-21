"""Render captured debugger text to a PNG so the agent can *read it as an image*
when plain-text extraction is unreliable (wrapping, unicode tables, etc.)."""

from __future__ import annotations

import io

from PIL import Image, ImageDraw, ImageFont


def _font(size: int = 15):
    for path in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
    ):
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            continue
    return ImageFont.load_default()


def text_to_png(text: str, title: str = "") -> bytes:
    if title:
        text = title + "\n" + ("-" * max(8, len(title))) + "\n" + text
    lines = text.replace("\t", "    ").split("\n")
    if not lines:
        lines = [""]
    # cap to keep the image sane
    lines = [ln[:300] for ln in lines[:400]]
    font = _font(15)
    line_h = 19
    pad = 12
    # measure width
    tmp = Image.new("RGB", (10, 10))
    d = ImageDraw.Draw(tmp)
    max_w = 1
    for ln in lines:
        try:
            w = d.textlength(ln, font=font)
        except Exception:
            w = len(ln) * 9
        max_w = max(max_w, int(w))
    W = min(2400, max_w + 2 * pad)
    H = line_h * len(lines) + 2 * pad
    img = Image.new("RGB", (W, H), (16, 18, 24))
    draw = ImageDraw.Draw(img)
    y = pad
    for ln in lines:
        color = (220, 223, 228)
        low = ln.lower()
        if "canary" in low:
            color = (255, 170, 90)
        elif "0x7f" in ln or "libc" in low:
            color = (120, 210, 255)
        elif "rip" in low or "rsp" in low or "rbp" in low:
            color = (160, 255, 160)
        elif "breakpoint" in low or "error" in low:
            color = (255, 120, 120)
        draw.text((pad, y), ln, font=font, fill=color)
        y += line_h
    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()
