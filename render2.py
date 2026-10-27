import pyte, sys
p = r"C:\Users\celnik__\Desktop\New folder (4)\_work\dump\drive.txt"
raw = open(p,'rb').read().decode('utf-8','replace')
for (w,h) in [(200,120),(240,160)]:
    screen = pyte.Screen(w,h); stream = pyte.Stream(screen); stream.feed(raw)
    lines=[l.rstrip() for l in screen.display]
    print(f"=== {w}x{h} cursor {screen.cursor.x},{screen.cursor.y} ===")
    for i,l in enumerate(lines):
        if any(k in l for k in ['MAIN','Select','SPOOF','Spoofer','MENU','[ 1 ]','[ 2 ]','[ 3 ]','[ 4 ]','Enter','Back','SUCCESS','FAILED','license','Username','Key','Settings','Discord','VanishTrace','Welcome']):
            print(f"{i:03}|{l}")
