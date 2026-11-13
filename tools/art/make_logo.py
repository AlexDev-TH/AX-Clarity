"""Render docs/images/logo.png (transparent, works on light and dark GitHub themes)."""
import os

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "docs", "images", "logo.png")
FONT = "C:/Windows/Fonts/ariblk.ttf"

W, H = 1700, 400
SIZE = 230
TRACK = 6          # letter spacing
DEPTH = 20         # 3D extrusion in px
STROKE = 9

PARTS = [
    ("AX", ((255, 138, 61), (230, 57, 0)), (122, 24, 0)),
    ("-", ((255, 220, 90), (255, 160, 30)), (140, 70, 0)),
    ("CLARITY", ((255, 236, 110), (255, 163, 26)), (150, 72, 0)),
]


def gradient(size, top, bottom):
    g = Image.new("RGBA", size)
    d = ImageDraw.Draw(g)
    for y in range(size[1]):
        t = y / max(1, size[1] - 1)
        c = tuple(int(top[i] + (bottom[i] - top[i]) * t) for i in range(3)) + (255,)
        d.line([(0, y), (size[0], y)], fill=c)
    return g


def main():
    font = ImageFont.truetype(FONT, SIZE)
    # lay out every glyph with tracking
    glyphs = []
    x = 0
    for text, grad, side in PARTS:
        for ch in text:
            w = font.getlength(ch)
            glyphs.append((ch, x, grad, side))
            x += w + TRACK
    total = x - TRACK
    asc, desc = font.getmetrics()
    ox = (W - total - DEPTH) / 2
    oy = (H - (asc + desc) - DEPTH) / 2 + 10

    img = Image.new("RGBA", (W, H), (0, 0, 0, 0))

    # soft drop shadow
    sh = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    sd = ImageDraw.Draw(sh)
    for ch, gx, _, _ in glyphs:
        sd.text((ox + gx + DEPTH + 10, oy + DEPTH + 16), ch, font=font, fill=(0, 0, 0, 150),
                stroke_width=STROKE, stroke_fill=(0, 0, 0, 150))
    img.alpha_composite(sh.filter(ImageFilter.GaussianBlur(12)))

    d = ImageDraw.Draw(img)
    # extrusion: dark side, then outline
    for i in range(DEPTH, 0, -1):
        for ch, gx, _, side in glyphs:
            d.text((ox + gx + i, oy + i), ch, font=font, fill=side + (255,),
                   stroke_width=STROKE, stroke_fill=(43, 14, 0, 255))
    for ch, gx, _, _ in glyphs:
        d.text((ox + gx, oy), ch, font=font, fill=(43, 14, 0, 255),
               stroke_width=STROKE, stroke_fill=(43, 14, 0, 255))

    # gradient faces
    for ch, gx, grad, _ in glyphs:
        mask = Image.new("L", (W, H), 0)
        ImageDraw.Draw(mask).text((ox + gx, oy), ch, font=font, fill=255)
        bbox = mask.getbbox()
        if not bbox:
            continue
        face = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        gh = bbox[3] - bbox[1]
        face.paste(gradient((bbox[2] - bbox[0], gh), grad[0], grad[1]), (bbox[0], bbox[1]))
        img.paste(face, (0, 0), mask)
        # glossy highlight on the upper part of each glyph
        hl = Image.new("L", (W, H), 0)
        ImageDraw.Draw(hl).rectangle([bbox[0], bbox[1], bbox[2], bbox[1] + int(gh * 0.38)], fill=70)
        hl = Image.composite(hl, Image.new("L", (W, H), 0), mask)
        white = Image.new("RGBA", (W, H), (255, 255, 255, 255))
        img.paste(white, (0, 0), hl)

    img = img.crop(img.getbbox())
    pad = 24
    out = Image.new("RGBA", (img.width + pad * 2, img.height + pad * 2), (0, 0, 0, 0))
    out.alpha_composite(img, (pad, pad))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    out.save(OUT, optimize=True)
    print("wrote", OUT, out.size)


if __name__ == "__main__":
    main()
