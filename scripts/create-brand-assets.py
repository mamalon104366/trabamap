"""Genera el icono y las imágenes del instalador de TrabaMap a partir del logo vectorial.

Uso: py -3 scripts/create-brand-assets.py   (requiere Pillow: py -3 -m pip install pillow)
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
BUILD.mkdir(parents=True, exist_ok=True)

BG = "#0b0b0e"
ACCENT = "#5b4bff"
ACCENT_HI = "#7d70ff"
WHITE = "#f4f4f7"
MUTED = "#9797a3"
LINE = "#26262d"

# La "T" angular de TrabaMap en un lienzo de 261 x 261 (el mismo trazado que src/icons.jsx).
LOGO_POINTS = [(22, 27), (232, 27), (149, 100), (149, 172), (154, 182), (130, 208), (111, 221),
               (92, 207), (120, 184), (120, 95), (165, 50), (97, 50), (76, 71)]


def logo(size: int, tile: bool = True) -> Image.Image:
    """Logo con supermuestreo para que los bordes diagonales salgan limpios."""
    factor = 4
    big = size * factor
    canvas = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    inset = 0.0
    if tile:
        # Fondo gris oscuro con un degradado radial suave, como el logo original.
        gradient = Image.radial_gradient("L").resize((big, big))
        dark = Image.new("RGBA", (big, big), "#1d1d22")
        light = Image.new("RGBA", (big, big), "#4a4a52")
        fill = Image.composite(dark, light, gradient)
        mask = Image.new("L", (big, big), 0)
        ImageDraw.Draw(mask).rounded_rectangle((0, 0, big - 1, big - 1), radius=round(big * 0.23), fill=255)
        canvas.paste(fill, (0, 0), mask)
        inset = 0.12
    scale = big * (1 - inset * 2) / 261
    offset = big * inset
    points = [(offset + x * scale, offset + y * scale) for x, y in LOGO_POINTS]
    ImageDraw.Draw(canvas).polygon(points, fill="#ffffff")
    return canvas.resize((size, size), Image.Resampling.LANCZOS)


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(Path(r"C:\Windows\Fonts") / name), size=size)


def save_icon() -> None:
    icon = logo(512)
    icon.save(BUILD / "trabamap.ico", format="ICO", sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (24, 24), (16, 16)])
    icon.save(BUILD / "trabamap-icon.png")


def save_sidebar() -> None:
    """Imagen lateral del instalador NSIS: 164 x 314 px."""
    scale = 2
    width, height = 164 * scale, 314 * scale
    image = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 4 * scale, height), fill=ACCENT)
    mark = logo(52 * scale)
    image.paste(mark, (20 * scale, 22 * scale), mark)
    draw.text((20 * scale, 86 * scale), "TrabaMap", fill=WHITE, font=font("seguisb.ttf", 22 * scale))
    draw.text((20 * scale, 116 * scale), "Explorador de red", fill=MUTED, font=font("segoeui.ttf", 11 * scale))
    draw.line((20 * scale, 142 * scale, 144 * scale, 142 * scale), fill=LINE, width=scale)
    for index, line in enumerate(("Tu red,", "en claro.")):
        draw.text((20 * scale, (156 + index * 24) * scale), line, fill=WHITE, font=font("seguisb.ttf", 19 * scale))
    for index, line in enumerate(("Equipos, puertos y", "servicios explicados", "en español.")):
        draw.text((20 * scale, (214 + index * 16) * scale), line, fill=MUTED, font=font("segoeui.ttf", 10 * scale))
    draw.line((20 * scale, 286 * scale, 144 * scale, 286 * scale), fill=LINE, width=scale)
    draw.text((20 * scale, 293 * scale), "Motor Nmap · datos locales", fill=ACCENT_HI, font=font("segoeui.ttf", 8 * scale))
    image.resize((164, 314), Image.Resampling.LANCZOS).save(BUILD / "installer-sidebar.bmp")


def save_splash() -> None:
    """Pantalla de carga de la versión portable: 640 x 290 px."""
    width, height = 640, 290
    image = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 6, height), fill=ACCENT)
    mark = logo(120)
    image.paste(mark, (48, 85), mark)
    draw.text((200, 84), "TrabaMap", fill=WHITE, font=font("seguisb.ttf", 48))
    draw.text((203, 146), "Explorador de red", fill=MUTED, font=font("segoeui.ttf", 20))
    draw.line((203, 190, 590, 190), fill=LINE, width=2)
    draw.text((203, 205), "Preparando tu espacio de trabajo…", fill=ACCENT_HI, font=font("segoeui.ttf", 16))
    image.save(BUILD / "portable-splash.bmp")


if __name__ == "__main__":
    save_icon()
    save_sidebar()
    save_splash()
    print(f"Recursos visuales creados en {BUILD}")
