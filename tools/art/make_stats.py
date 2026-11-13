"""Render stat tiles from a benchmark result file.

  python tools/art/make_stats.py <name_bench.txt> <out.png> "<title>"
"""
import sys

from PIL import Image, ImageDraw, ImageFont

THAI = "C:/Windows/Fonts/LeelawUI.ttf"
THAI_B = "C:/Windows/Fonts/LeelaUIb.ttf"
NUM = "C:/Windows/Fonts/bahnschrift.ttf"

BG = (13, 17, 23)
TILE = (22, 27, 34)
BORDER = (48, 54, 61)
INK = (230, 237, 243)
INK2 = (173, 186, 199)
MUTED = (125, 133, 144)
ACCENT = (255, 159, 26)

TILES = [
    ("unnamed globals (DAT_)", "ตัวแปร global ไม่มีชื่อ", "DAT_xxxx"),
    ("base register arithmetic (gp+0x..)", "ตัวแปรที่อ้างผ่าน gp + offset", "*(unaff_gp + -0x7876)"),
    ("undefined types", "ชนิดข้อมูล undefined", "undefined2 / undefined4"),
    ("type casts", "type cast ในโค้ด", "(uint)(ushort)x"),
    ("chars", "ความยาวโค้ดรวม", "ตัวอักษรไม่นับช่องว่าง"),
    ("WARNING comments", "WARNING ที่รกหน้าจอ", "คอมเมนต์เตือนของ decompiler"),
]


def fmt_pct(a, c):
    """Percent reduction; never shows 100 unless the count really reached zero."""
    if a == 0:
        return "0"
    if c == 0:
        return "100"
    p = 100 * (a - c) / a
    if p >= 99:
        return f"{int(p * 10) / 10:.1f}"
    return str(round(p))


def read(path):
    rows = {}
    for line in open(path, encoding="utf-8"):
        p = line.rstrip("\n").split("\t")
        if len(p) == 4 and p[1].isdigit():
            rows[p[0]] = (int(p[1]), int(p[2]), int(p[3]))
    return rows


def main():
    src, out, title = sys.argv[1:4]
    rows = read(src)
    cols, tw, th, gap, pad = 3, 400, 196, 18, 30
    W = pad * 2 + cols * tw + (cols - 1) * gap
    H = 96 + 2 * th + gap + pad
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.text((pad, 26), title, font=ImageFont.truetype(THAI_B, 26), fill=INK)
    d.text((pad, 62), "Ghidra เดิม เทียบกับ AX-Clarity บนไฟล์เดียวกัน ทุกฟังก์ชันในรอม",
           font=ImageFont.truetype(THAI, 17), fill=MUTED)
    for i, (key, label, hint) in enumerate(TILES):
        a, _, c = rows[key]
        pct = fmt_pct(a, c)
        x = pad + (i % cols) * (tw + gap)
        y = 96 + (i // cols) * (th + gap)
        d.rounded_rectangle([x, y, x + tw, y + th], radius=16, fill=TILE, outline=BORDER, width=2)
        d.rounded_rectangle([x, y + 18, x + 5, y + th - 18], radius=2, fill=ACCENT)
        d.text((x + 24, y + 18), label, font=ImageFont.truetype(THAI_B, 20), fill=INK2)
        big = f"-{pct}%"
        d.text((x + 22, y + 52), big, font=ImageFont.truetype(NUM, 64), fill=INK)
        d.text((x + 24, y + 134), f"{a:,}  เหลือ  {c:,}", font=ImageFont.truetype(THAI_B, 19), fill=ACCENT)
        d.text((x + 24, y + 162), hint, font=ImageFont.truetype(THAI, 15), fill=MUTED)
    img.save(out, optimize=True)
    print("wrote", out, img.size)


if __name__ == "__main__":
    main()
