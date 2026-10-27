import pyte, sys, os
p = r"C:\Users\celnik__\Desktop\New folder (4)\_work\dump\drive.txt"
raw = open(p,'rb').read().decode('utf-8','replace')
screen = pyte.Screen(160, 60)
stream = pyte.Stream(screen)
# feed in chunks to keep it responsive
stream.feed(raw)
lines = [l.rstrip() for l in screen.display]
while lines and not lines[-1].strip(): lines.pop()
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
print("cursor", screen.cursor.x, screen.cursor.y, "lines", len(lines))
for i,l in enumerate(lines):
    if l.strip(): print(f"{i:02}|{l}")
