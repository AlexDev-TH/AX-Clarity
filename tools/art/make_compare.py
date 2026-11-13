"""Render a side-by-side image: Ghidra output vs AX-Clarity output of the same function.

  python tools/art/make_compare.py <samples.txt> <function_addr> <out.png> [title]

<samples.txt> is written by tools/benchmark/AXClarityBenchmark.java.
"""
import os
import re
import sys

from PIL import Image, ImageDraw, ImageFont

USER_FONTS = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Windows", "Fonts")
MONO = os.path.join(USER_FONTS, "JetBrainsMono-Regular.ttf")
THAI = "C:/Windows/Fonts/LeelawUI.ttf"
THAI_B = "C:/Windows/Fonts/LeelaUIb.ttf"

BG = (13, 17, 23)
PANEL = (22, 27, 34)
BORDER = (48, 54, 61)
INK = (230, 237, 243)
MUTED = (139, 148, 158)
ACCENT = (255, 159, 26)
BAD = (255, 123, 114)

C = {
    "plain": (212, 212, 212), "kw": (197, 134, 192), "type": (78, 201, 176), "num": (181, 206, 168),
    "cmt": (106, 153, 85), "cal": (255, 180, 84), "ram": (156, 220, 254), "io": (255, 123, 156),
    "func": (220, 220, 170), "macro": (255, 209, 102), "warn": (255, 85, 85),
}
KW = set("if else while for do switch case default return break continue goto sizeof".split())
TYPES = set(("u8 s8 u16 s16 u24 s24 u32 s32 u64 s64 void bool char short int long uint ushort uchar byte ulong "
             "float double code undefined undefined1 undefined2 undefined3 undefined4 undefined8 uint3 sbyte").split())
MACROS = {"BIT", "SETBIT", "CLRBIT"}
TOKEN = re.compile(r"/\*.*?\*/|//.*|[A-Za-z_]\w*|0[xX][0-9a-fA-F]+|\d+|\s+|.", re.S)


def font(path, size):
    try:
        return ImageFont.truetype(path, size)
    except OSError:
        return ImageFont.truetype("C:/Windows/Fonts/consola.ttf", size)


def color_of(tok, line, end):
    if tok.startswith("/*=") :
        return C["num"]
    if tok.startswith("/*") or tok.startswith("//"):
        return C["cmt"]
    if re.match(r"[A-Za-z_]", tok):
        if tok in KW:
            return C["kw"]
        if tok in MACROS:
            return C["macro"]
        if tok in TYPES:
            return C["type"]
        if tok.startswith("cal_"):
            return C["cal"]
        if tok.startswith(("ram_", "DAT_", "_DAT_")):
            return C["ram"]
        if tok.startswith("io_"):
            return C["io"]
        if tok.startswith(("unaff_", "in_", "extraout_")):
            return C["warn"]
        if line[end:].lstrip().startswith("("):
            return C["func"]
        return C["plain"]
    if re.match(r"\d", tok):
        return C["num"]
    return C["plain"]


def parse(samples, addr):
    text = open(samples, encoding="utf-8").read()
    parts = re.split(r"^######## (.*)$", text, flags=re.M)
    cur = None
    out = {}
    for i in range(1, len(parts), 2):
        head, body = parts[i].strip(), parts[i + 1]
        if re.fullmatch(r"[0-9a-fA-F]+", head):
            cur = head
            continue
        if cur == addr:
            out[head.split()[0]] = body.strip("\n")
    return out["A"], out["C"]


def draw_code(d, x, y, lines, f, lh, maxw):
    for ln in lines:
        cx = x
        pos = 0
        for m in TOKEN.finditer(ln):
            tok = m.group(0)
            col = color_of(tok, ln, m.end())
            w = d.textlength(tok, font=f)
            if cx + w > x + maxw:
                d.text((cx, y), "…", font=f, fill=MUTED)
                break
            d.text((cx, y), tok, font=f, fill=col)
            cx += w
            pos = m.end()
        y += lh


def main():
    samples, addr, out = sys.argv[1:4]
    title = sys.argv[4] if len(sys.argv) > 4 else ""
    a, c = parse(samples, addr)
    a_lines = [l.rstrip() for l in a.split("\n")]
    c_lines = [l.rstrip() for l in c.split("\n")]
    while a_lines and not a_lines[-1]:
        a_lines.pop()
    while c_lines and not c_lines[-1]:
        c_lines.pop()

    size = 15
    f = font(MONO, size)
    lh = int(size * 1.55)
    tmp = ImageDraw.Draw(Image.new("RGB", (10, 10)))
    a_w = max(tmp.textlength(l, font=f) for l in a_lines)
    c_w = max(tmp.textlength(l, font=f) for l in c_lines)
    col_w = int(min(max(a_w, c_w), 900))
    pad = 28
    head_h = 92
    rows = max(len(a_lines), len(c_lines))
    panel_h = rows * lh + 70
    W = pad * 3 + col_w * 2 + 48
    H = head_h + panel_h + pad * 2

    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    # window chrome
    for i, col in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([pad + i * 22, 24, pad + i * 22 + 13, 37], fill=col)
    tf = font(THAI_B, 24)
    d.text((pad + 80, 16), title, font=tf, fill=INK)

    def panel(px, label, sub, lines, n_lines, chars, accent):
        d.rounded_rectangle([px, head_h, px + col_w + 24, head_h + panel_h], radius=14, fill=PANEL,
                            outline=BORDER, width=2)
        d.rounded_rectangle([px, head_h, px + 6, head_h + panel_h], radius=3, fill=accent)
        d.text((px + 20, head_h + 14), label, font=font(THAI_B, 20), fill=INK)
        d.text((px + 20 + d.textlength(label, font=font(THAI_B, 20)) + 14, head_h + 18), sub,
               font=font(THAI, 16), fill=MUTED)
        draw_code(d, px + 20, head_h + 56, lines, f, lh, col_w - 4)

    def stats(lines):
        body = [l for l in lines if l.strip() and not l.startswith("// BIT(")]
        chars = sum(len(re.sub(r"\s+", "", re.sub(r"/\*=[^*]*\*/", "", l))) for l in body)
        return len(body), chars

    an, ac = stats(a_lines)
    cn, cc = stats(c_lines)
    panel(pad, "Ghidra เดิม", f"{an} บรรทัด  {ac:,} ตัวอักษร", a_lines, an, ac, BAD)
    panel(pad * 2 + col_w + 24, "AX-Clarity", f"{cn} บรรทัด  {cc:,} ตัวอักษร  (สั้นลง {round(100 * (ac - cc) / ac)}%)",
          c_lines, cn, cc, ACCENT)
    img.save(out, optimize=True)
    print("wrote", out, img.size)


if __name__ == "__main__":
    main()
