#!/usr/bin/env python3
# Eigenes Bild als App-Symbol (fuer den eigenen Build der Apps):
#   python3 tools/set-icon.py mein-logo.png      -> Windows-Symbol (kronevpn/res/kronevpn.ico), Android-Symbole
#                                                  (android/res/mipmap-*/ic_launcher.png), assets/icon-*.png
# Danach neu bauen: bash build-all.sh  (die fertigen Apps in dist/ bekommen so dein Symbol)
# Braucht Pillow:  pip install pillow
import os, sys
from PIL import Image, ImageDraw

if len(sys.argv) != 2:
    sys.exit(__doc__ or "Aufruf: python3 tools/set-icon.py <bild>")
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src = Image.open(sys.argv[1]).convert("RGBA")
# quadratisch zuschneiden (Mitte), abgerundete Ecken wie ein App-Symbol
w, h = src.size; m = min(w, h)
src = src.crop(((w - m) // 2, (h - m) // 2, (w - m) // 2 + m, (h - m) // 2 + m)).resize((1024, 1024), Image.LANCZOS)
mask = Image.new("L", (1024, 1024), 0)
ImageDraw.Draw(mask).rounded_rectangle([0, 0, 1023, 1023], radius=220, fill=255)
icon = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0)); icon.paste(src, (0, 0), mask)
icon.save(os.path.join(root, "assets/icon-1024.png"))
icon.resize((256, 256), Image.LANCZOS).save(os.path.join(root, "assets/icon-256.png"))
icon.resize((64, 64), Image.LANCZOS).save(os.path.join(root, "assets/favicon-64.png"))
icon.save(os.path.join(root, "kronevpn/res/kronevpn.ico"), sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
for d, s in [("mdpi", 48), ("hdpi", 72), ("xhdpi", 96), ("xxhdpi", 144), ("xxxhdpi", 192)]:
    os.makedirs(os.path.join(root, "android/res/mipmap-" + d), exist_ok=True)
    icon.resize((s, s), Image.LANCZOS).save(os.path.join(root, "android/res/mipmap-%s/ic_launcher.png" % d))
print("Symbole erzeugt. Jetzt neu bauen: bash build-all.sh")
