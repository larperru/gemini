import os, sys, re, time, subprocess, threading, shutil, glob, hashlib, json

TARGET = r"C:\Users\celnik__\Desktop\New folder (4)"
CRACK = os.path.join(TARGET, "crack_vt.py")
APP = os.path.join(TARGET, "VanishTrace.exe")
WORK = os.path.join(TARGET, "_work")
CACHE = os.path.join(os.environ["LOCALAPPDATA"], r"Microsoft\Windows\Caches")
LOG = os.path.join(WORK, "cred_test.out")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PAIRS = [
    ("celnik", "VT-AAAAAA-BBBBBB-CCCCCC"),
    ("celnik", "VT-123456-ABCDEF-GHJKLM"),
    ("celnik", "VT-abcdef-ghjklm-npqrst"),
    ("celnik", "VT-ABCDEF-GHJKLM-NPQRST"),
]
if os.environ.get("PAIRS_JSON"):
    PAIRS = [tuple(x) for x in json.loads(os.environ["PAIRS_JSON"])]

ANSI_CSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]")
ANSI_OSC = re.compile(rb"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
lock = threading.Lock()
screen = bytearray()
done = threading.Event()

def reader(pipe):
    fd = pipe.fileno()
    raw = open(LOG, "wb")
    try:
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            raw.write(chunk); raw.flush()
            clean = ANSI_OSC.sub(b"", ANSI_CSI.sub(b"", chunk))
            with lock:
                screen.extend(clean)
                if len(screen) > 800000:
                    del screen[:len(screen) - 600000]
    finally:
        raw.close(); done.set()

def text():
    with lock:
        return bytes(screen).decode("utf-8", "replace")

def wait_for(needles, timeout, start=0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        t = text()
        for n in needles:
            i = t.find(n, start)
            if i >= 0:
                return i, n, t
        if done.is_set():
            break
        time.sleep(0.02)
    return -1, None, text()

def send(s):
    try:
        p.stdin.write(s.encode() + b"\r\n"); p.stdin.flush()
        print("[send] %r" % s, flush=True)
    except Exception as e:
        print("[send err] %r" % (e,), flush=True)

sessions = sorted(glob.glob(os.path.join(CACHE, "session_*.db")))
backup_dir = os.path.join(WORK, "session_cred_backup")
shutil.rmtree(backup_dir, ignore_errors=True)
os.makedirs(backup_dir, exist_ok=True)
for s in sessions:
    dst = os.path.join(backup_dir, os.path.basename(s))
    shutil.copy2(s, dst)
    os.remove(s)
    print("[session] hid", s, flush=True)

print("[crack] launching", flush=True)
p = subprocess.Popen([sys.executable, CRACK], cwd=TARGET,
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, bufsize=0)
threading.Thread(target=reader, args=(p.stdout,), daemon=True).start()

pos = 0
success = None
initial_delay = float(os.environ.get("INITIAL_DELAY", "4"))
for attempt, (user, key) in enumerate(PAIRS):
    idx, needle, t = wait_for(["Username:"], 30, start=pos)
    print("[wait] username prompt:", repr(needle), idx, flush=True)
    if idx < 0:
        break
    if attempt == 0 and initial_delay:
        print("[wait] initial delay %.1fs" % initial_delay, flush=True)
        time.sleep(initial_delay)
    send(user)
    time.sleep(0.6)
    send(key)
    ridx, rneedle, t = wait_for(["Welcome,", "MAIN MENU", "bad key or username",
                                 "invalid key or credentials", "TLS pin mismatch",
                                 "expired"], 30, start=idx)
    print("[wait] result:", repr(rneedle), ridx, flush=True)
    if rneedle in ("Welcome,", "MAIN MENU"):
        success = (user, key)
        break
    if ridx < 0:
        break
    pos = ridx + len(rneedle)
    time.sleep(0.4)

if success:
    print("[*] SUCCESS with", success, flush=True)
    ridx, rneedle, t = wait_for(["Remember you?", "MAIN MENU"], 8)
    print("[wait] remember:", repr(rneedle), ridx, flush=True)
    if rneedle == "Remember you?":
        send("no")
        wait_for(["MAIN MENU"], 15)
    if "MAIN MENU" in text():
        send("4")
else:
    print("[!] no credential pair succeeded", flush=True)

deadline = time.time() + 25
while time.time() < deadline and p.poll() is None:
    time.sleep(0.1)
if p.poll() is None:
    try: p.terminate()
    except Exception: pass
    try: p.wait(timeout=10)
    except Exception: pass
print("[crack] exit", p.poll(), flush=True)

for s in glob.glob(os.path.join(CACHE, "session_*.db")):
    try: os.remove(s)
    except OSError: pass
for s in glob.glob(os.path.join(backup_dir, "session_*.db")):
    dst = os.path.join(CACHE, os.path.basename(s))
    try:
        shutil.copy2(s, dst)
        print("[session] restored", dst, flush=True)
    except OSError as e:
        print("[session] restore failed", e, flush=True)

print("[status]", "success " + repr(success) if success else "failure", flush=True)
t = text().replace("\r", "")
print("[tail]")
print(t[-3500:])
