import os, sys, re, time, subprocess, threading, shutil, glob, json, hashlib

TARGET = r"C:\Users\celnik__\Desktop\New folder (4)"
CRACK = os.path.join(TARGET, "crack_vt.py")
APP = os.path.join(TARGET, "VanishTrace.exe")
WORK = os.path.join(TARGET, "_work")
CACHE = os.path.join(os.environ["LOCALAPPDATA"], r"Microsoft\Windows\Caches")
MODE = os.environ.get("MODE", "auto")
REMEMBER = os.environ.get("REMEMBER", "no")
TEST_USER = os.environ.get("TEST_USER", "tester")
TEST_KEY = os.environ.get("TEST_KEY", "VT-ABCDEF-GHJKLM-NPQRST")
LOG = os.path.join(WORK, "final_%s.out" % MODE)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

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

# --- session backup / hide ---
sessions = sorted(glob.glob(os.path.join(CACHE, "session_*.db")))
backup_dir = os.path.join(WORK, "session_final_backup")
shutil.rmtree(backup_dir, ignore_errors=True)
os.makedirs(backup_dir, exist_ok=True)
for s in sessions:
    dst = os.path.join(backup_dir, os.path.basename(s))
    shutil.copy2(s, dst)
    print("[session] backed up", s, os.path.getsize(dst), flush=True)

if MODE == "manual":
    for s in sessions:
        try:
            os.remove(s)
            print("[session] hidden", s, flush=True)
        except OSError as e:
            print("[session] could not hide", s, e, flush=True)

print("[hash before]", hashlib.sha256(open(APP, "rb").read()).hexdigest(), flush=True)
print("[crack] launching", flush=True)

p = subprocess.Popen([sys.executable, CRACK], cwd=TARGET,
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, bufsize=0)
threading.Thread(target=reader, args=(p.stdout,), daemon=True).start()

status = "timeout"
idx, needle, t = wait_for(["Username:", "MAIN MENU", "Auto-Sign In successful", "TLS pin mismatch"], 70)
print("[wait] first:", repr(needle), idx, flush=True)

if MODE == "manual" and needle == "Username:":
    pre = float(os.environ.get("SEND_DELAY", "0"))
    if pre:
        print("[wait] delaying credentials %.1fs" % pre, flush=True)
        time.sleep(pre)
    send(TEST_USER)
    time.sleep(0.7)
    send(TEST_KEY)
    idx2, needle2, t = wait_for(["Welcome,", "MAIN MENU", "TLS pin mismatch",
                                 "bad key or username", "expired"], 45)
    print("[wait] login result:", repr(needle2), idx2, flush=True)
    if needle2 == "Welcome," or needle2 == "MAIN MENU":
        status = "login"
elif MODE == "auto" and needle in ("MAIN MENU", "Auto-Sign In successful"):
    status = "auto"
    idx2, needle2, t = wait_for(["MAIN MENU"], 30)
    print("[wait] menu:", repr(needle2), idx2, flush=True)

if status in ("login", "auto"):
    # if the app asks to remember, answer (default no)
    if status == "login":
        ridx, rneedle, t = wait_for(["Remember you?", "MAIN MENU"], 8)
        print("[wait] remember:", repr(rneedle), ridx, flush=True)
        if rneedle == "Remember you?":
            send(REMEMBER)
            midx, mneedle, t = wait_for(["MAIN MENU"], 15)
            print("[wait] menu after remember:", repr(mneedle), midx, flush=True)
            if mneedle:
                status = "menu"
    else:
        midx, mneedle, t = wait_for(["MAIN MENU"], 20)
        if mneedle:
            status = "menu"

    if "MAIN MENU" in text():
        send("1")                       # Spoofers
        sidx, sneedle, t = wait_for(["SPOOFERS", "PICK A SPOOFER"], 15)
        print("[wait] spoofers:", repr(sneedle), sidx, flush=True)
        if sneedle:
            sleep = 1.0
            time.sleep(sleep)
            hold = float(os.environ.get("HOLD_SECONDS", "0"))
            if hold:
                print("[hold] staying in spoofers for %.0fs" % hold, flush=True)
                time.sleep(hold)
            send("")                    # back
            time.sleep(1.0)
            send("4")                   # exit
        else:
            send("4")
        status = "menu+spoofers" if sneedle else status

# If the app never got to a menu, terminate.
deadline = time.time() + 25
while time.time() < deadline and p.poll() is None:
    time.sleep(0.1)
if p.poll() is None:
    print("[!] crack still running; terminating", flush=True)
    try: p.terminate()
    except Exception: pass
    try: p.wait(timeout=10)
    except Exception: pass
print("[crack] exit", p.poll(), flush=True)
time.sleep(0.5)

# restore sessions if manual
if MODE == "manual":
    for s in glob.glob(os.path.join(CACHE, "session_*.db")):
        try: os.remove(s)
        except OSError: pass
    for s in glob.glob(os.path.join(backup_dir, "session_*.db")):
        dst = os.path.join(CACHE, os.path.basename(s))
        try:
            shutil.copy2(s, dst)
            print("[session] restored", dst, os.path.getsize(dst), flush=True)
        except OSError as e:
            print("[session] restore failed", e, flush=True)

print("[hash after]", hashlib.sha256(open(APP, "rb").read()).hexdigest(), flush=True)
print("[status]", status, flush=True)
t = text().replace("\r", "")
print("[tail]")
print(t[-5000:])
