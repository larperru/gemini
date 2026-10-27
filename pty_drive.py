import os, sys, time, threading
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
os.environ['__COMPAT_LAYER'] = 'RunAsInvoker'
import pyte
from winpty import PtyProcess

EXE = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
COLS, ROWS = 160, 40
screen = pyte.Screen(COLS, ROWS)
stream = pyte.Stream(screen)
lock = threading.Lock()

p = PtyProcess.spawn([EXE], dimensions=(ROWS, COLS))
print("spawned pid", getattr(p, 'pid', '?'), flush=True)

def reader():
    while True:
        try: data = p.read(65536)
        except Exception: break
        if not data: break
        with lock:
            try: stream.feed(data)
            except Exception: pass

threading.Thread(target=reader, daemon=True).start()

def snap(tag):
    with lock:
        lines = [l.rstrip() for l in screen.display]
    while lines and not lines[-1].strip(): lines.pop()
    out = [f"===== {tag} cursor=({screen.cursor.x},{screen.cursor.y}) ====="]
    for i,l in enumerate(lines):
        if l.strip(): out.append(f"{i:02}|{l}")
    txt = "\n".join(out)
    print(txt, flush=True)
    with open(rf"C:\Users\celnik__\Desktop\New folder (4)\_work\dump\pty_{tag}.txt", 'w', encoding='utf-8') as f:
        f.write(txt)

time.sleep(8); snap("start")
if p.isalive():
    p.write("1\r"); time.sleep(5); snap("after1")
if p.isalive():
    p.write("4\r"); time.sleep(3); snap("after4")
if p.isalive():
    p.terminate()
print("done", flush=True)
