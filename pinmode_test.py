import os, sys, ssl, socket, threading, time, json, subprocess, tempfile, re, importlib.util, ctypes, hashlib
from ctypes import wintypes

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
CRACK_PY = r"C:\Users\celnik__\Downloads\crack.py"
spec = importlib.util.spec_from_file_location("vtcrack", CRACK_PY)
vtc = importlib.util.module_from_spec(spec); spec.loader.exec_module(vtc)

EXE = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
WORK = r"C:\Users\celnik__\Desktop\New folder (4)\_work"
MODE = os.environ.get("PIN_MODE", "none")          # none | early | late
PATCH_DELAY = float(os.environ.get("PATCH_DELAY", "3.0"))
LOGIN = os.environ.get("LOGIN", "1") == "1"
SCAN_IMAGE = os.environ.get("SCAN_IMAGE", "0") == "1"
TAG = os.environ.get("TAG", MODE)
LOG = os.path.join(WORK, f"pinmode_{TAG}.log")
RAWOUT = os.path.join(WORK, "dump", f"pinmode_{TAG}.raw")
PROXY_PORT = 8443
PAC_PORT = 8444
PIN_OFFSETS = [0x10C420, 0x10C440]
REAL_PIN = bytes.fromhex("b3e8bc059cf27952ce73481e81c9019581403d0d42232d9ad53c16a4eedafe8d")

from cryptography import x509
from cryptography.hazmat.primitives import serialization
fake_der = ssl.PEM_cert_to_DER_cert(vtc.CRT_PEM)
fake_spki = x509.load_der_x509_certificate(fake_der).public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
FAKE_PIN = hashlib.sha256(fake_spki).digest()

logf = open(LOG, "w", encoding="utf-8", buffering=1)
t0 = time.time()
def log(*a):
    s = " ".join(str(x) for x in a)
    print("[%7.3f] %s" % (time.time() - t0, s), flush=True)
    logf.write("[%7.3f] %s\n" % (time.time() - t0, s))

tmp = tempfile.mkdtemp(prefix="vt_pinmode_")
ca, crt, key = vtc.write_pems(tmp)
r = subprocess.run(["certutil", "-user", "-addstore", "-f", "Root", ca], capture_output=True, text=True, errors="ignore")
log("[ca] addstore rc", r.returncode)

PROXY_HOST = "vanishtrace.authvt.workers.dev"
PAC = ("function FindProxyForURL(url, host) {\n"
       f'  if (host === "{PROXY_HOST}") return "PROXY 127.0.0.1:{PROXY_PORT}";\n'
       '  return "DIRECT";\n}\n')
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class PacHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        data = PAC.encode(); self.send_response(200)
        self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def log_message(self, *a): pass
pac_srv = ThreadingHTTPServer(("127.0.0.1", PAC_PORT), PacHandler)
threading.Thread(target=pac_srv.serve_forever, daemon=True).start()
log("[pac] listening", PAC_PORT)

import winreg
keypath = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg = winreg.OpenKey(winreg.HKEY_CURRENT_USER, keypath, 0, winreg.KEY_READ)
def getv(n, d=None):
    try: return winreg.QueryValueEx(reg, n)[0]
    except OSError: return d
old = {n: getv(n) for n in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL")}
reg.Close()
log("[proxy] old", old)
reg = winreg.OpenKey(winreg.HKEY_CURRENT_USER, keypath, 0, winreg.KEY_SET_VALUE)
winreg.SetValueEx(reg, "ProxyEnable", 0, winreg.REG_DWORD, 0)
winreg.SetValueEx(reg, "AutoConfigURL", 0, winreg.REG_SZ, f"http://127.0.0.1:{PAC_PORT}/proxy.pac")
reg.Close()

ctxssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctxssl.load_cert_chain(crt, key)
reqs = []; req_lock = threading.Lock()
def serve_conn(c):
    try:
        c.settimeout(15); buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            d = c.recv(4096)
            if not d: return
            buf += d
        c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        t = ctxssl.wrap_socket(c, server_side=True); data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            d = t.recv(4096)
            if not d: return
            data += d
        lines = data.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace").splitlines()
        reqline = lines[0] if lines else ""
        hdrs = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1); hdrs[k.strip().lower()] = v.strip()
        clen = int(hdrs.get("content-length") or 0)
        body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
        while len(body) < clen:
            d = t.recv(4096)
            if not d: break
            body += d
        parts = reqline.split(" "); method = parts[0] if parts else "?"; path = parts[1] if len(parts) > 1 else "/"
        try: req = json.loads(body) if body else {}
        except Exception: req = {}
        user = req.get("username") or vtc.DEFAULT_USER
        clean = path.split("?")[0]
        if clean.endswith("/api/hash"): obj = {"sha256": None}
        elif clean.endswith("/api/nonce"): obj = {"nonce": "a" * 32}
        else: obj = {"ok": True, "username": user, "expiresAt": vtc.EXPIRES_MS}
        out = json.dumps(obj, separators=(",", ":")).encode()
        t.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(out)).encode() +
                  b"\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n" + out)
        with req_lock: reqs.append((round(time.time() - t0, 3), method, path, body[:400].decode("utf-8", "replace")))
        log("[request]", method, path)
        try: t.close()
        except Exception: pass
    except Exception as e:
        log("[conn err]", repr(e))
    finally:
        try: c.close()
        except Exception: pass

def acceptor(srv):
    while True:
        try: c, a = srv.accept()
        except OSError: return
        threading.Thread(target=serve_conn, args=(c,), daemon=True).start()
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PROXY_PORT)); srv.listen(16)
threading.Thread(target=acceptor, args=(srv,), daemon=True).start()
log("[proxy] listening", PROXY_PORT)

# memory
k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualProtectEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
k32.CloseHandle.argtypes = [wintypes.HANDLE]
class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD), ("PartitionId", wintypes.WORD),
                ("alignment1", wintypes.WORD), ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD), ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD), ("alignment2", wintypes.DWORD)]
k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                ("GlblcntUsage", wintypes.DWORD), ("ProccntUsage", wintypes.DWORD), ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", wintypes.DWORD), ("hModule", ctypes.c_void_p), ("szModule", wintypes.WCHAR*256),
                ("szExePath", wintypes.WCHAR*260)]
def module_info(pid):
    k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    k32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    snap = k32.CreateToolhelp32Snapshot(8 | 16, pid)
    if not snap or snap == ctypes.c_void_p(-1).value: return None, None
    me = MODULEENTRY32W(); me.dwSize = ctypes.sizeof(me)
    try:
        ok = k32.Module32FirstW(snap, ctypes.byref(me))
        while ok:
            if me.szModule.lower() == "vanishtrace.exe":
                return int(me.modBaseAddr or 0), int(me.modBaseSize or 0)
            ok = k32.Module32NextW(snap, ctypes.byref(me))
    finally: k32.CloseHandle(snap)
    return None, None

def read_mem(h, addr, n):
    buf = ctypes.create_string_buffer(n); rd = ctypes.c_size_t()
    if k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(rd)) and rd.value == n:
        return buf.raw
    return None
def write_mem(h, addr, data):
    oldp = wintypes.DWORD()
    if not k32.VirtualProtectEx(h, ctypes.c_void_p(addr), len(data), 0x04, ctypes.byref(oldp)):
        return False, ctypes.get_last_error()
    w = ctypes.c_size_t()
    ok = bool(k32.WriteProcessMemory(h, ctypes.c_void_p(addr), data, len(data), ctypes.byref(w)) and w.value == len(data))
    k32.VirtualProtectEx(h, ctypes.c_void_p(addr), len(data), oldp.value, ctypes.byref(oldp))
    return ok, 0

stop_evt = threading.Event()
pin_events = []
patched_addrs = set()

def pin_thread(pid):
    if MODE == "none":
        log("[pin] mode none"); return
    h = k32.OpenProcess(0x1F0FFF, False, pid)
    if not h:
        log("[pin] openfail", ctypes.get_last_error()); return
    base = None
    for _ in range(500):
        base, msize = module_info(pid)
        if base: break
        time.sleep(0.01)
    log("[pin] base", hex(base or 0), "size", hex(msize or 0), "mode", MODE)
    if not base: return
    if MODE == "late":
        time.sleep(PATCH_DELAY)
        log("[pin] late patch begins")
    while not stop_evt.is_set():
        for off in PIN_OFFSETS:
            va = base + off
            cur = read_mem(h, va, 32)
            if cur == REAL_PIN:
                ok, err = write_mem(h, va, FAKE_PIN)
                chk = read_mem(h, va, 32)
                pin_events.append((round(time.time() - t0, 4), hex(va), ok, chk == FAKE_PIN))
                log("[pin] write", hex(va), "ok", ok, "readback", chk == FAKE_PIN)
                if ok: patched_addrs.add(va)
            elif cur == FAKE_PIN and va in patched_addrs:
                # stayed patched; don't log every tick
                pass
        time.sleep(0.002)
    log("[pin] done; events", pin_events)
    k32.CloseHandle(h)

ANSI_CSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]")
ANSI_OSC = re.compile(rb"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
screen_lock = threading.Lock(); screen = bytearray(); reader_done = threading.Event()
def reader(pipe):
    rawf = open(RAWOUT, "wb")
    try:
        fd = pipe.fileno()
        while True:
            chunk = os.read(fd, 4096)
            if not chunk: break
            rawf.write(chunk); rawf.flush()
            clean = ANSI_CSI.sub(b"", ANSI_OSC.sub(b"", chunk))
            with screen_lock:
                screen.extend(clean)
                if len(screen) > 400000: del screen[:len(screen) - 300000]
    except Exception as e: log("[reader err]", repr(e))
    finally:
        rawf.close(); reader_done.set(); log("[reader] EOF")
def screen_text():
    with screen_lock: return bytes(screen).decode("utf-8", "replace")
def wait_for(needles, timeout, start=0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        t = screen_text()
        for n in needles:
            i = t.find(n, start)
            if i >= 0: return i, n, t
        if reader_done.is_set(): break
        time.sleep(0.02)
    return -1, None, screen_text()

env = dict(os.environ); env["__COMPAT_LAYER"] = "RunAsInvoker"
os.makedirs(os.path.dirname(RAWOUT), exist_ok=True)
p = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
log("[app] pid", p.pid)
threading.Thread(target=reader, args=(p.stdout,), daemon=True).start()
threading.Thread(target=pin_thread, args=(p.pid,), daemon=True).start()

status = "timeout"
idx, needle, text = wait_for(["Username:", "MAIN MENU", "Welcome,"], 40)
log("[wait] trigger", repr(needle), "at", idx)
if LOGIN and needle == "Username:":
    if MODE == "late":
        # wait until the late patch had a chance
        deadline = time.time() + max(0, PATCH_DELAY + 1.0)
        while time.time() < deadline and not patched_addrs:
            time.sleep(0.02)
    log("[state] patched:", [hex(a) for a in patched_addrs])
    time.sleep(0.2)
    try:
        p.stdin.write(b"tester\r\n"); p.stdin.flush(); log("[stdin] username")
    except Exception as e: log("[stdin err]", e)
    time.sleep(0.6)
    try:
        p.stdin.write(b"VT-ABCDEF-GHJKLM-NPQRST\r\n"); p.stdin.flush(); log("[stdin] key")
    except Exception as e: log("[stdin err]", e)
    idx2, needle2, text2 = wait_for(["Welcome,", "MAIN MENU", "TLS pin mismatch", "bad key or username", "expired"], 30)
    log("[wait] result", repr(needle2), "at", idx2)
    if needle2:
        status = "success" if ("Welcome," in needle2 or "MAIN MENU" in needle2) else "fail:" + needle2
    if status == "success":
        # answer remember prompt if shown
        ridx, rneedle, rtext = wait_for(["Remember you?", "MAIN MENU"], 8, start=max(0, idx2))
        log("[wait] remember", repr(rneedle), "at", ridx)
        if rneedle == "Remember you?":
            try:
                ans = os.environ.get("REMEMBER", "no")
                p.stdin.write(ans.encode() + b"\r\n"); p.stdin.flush(); log("[stdin] remember=" + ans)
            except Exception as e: log("[stdin err]", e)
            midx, mneedle, mtext = wait_for(["MAIN MENU", "Select option"], 10, start=len(rtext))
            log("[wait] mainmenu", repr(mneedle), "at", midx)
            if mneedle: status = "menu"
        elif rneedle == "MAIN MENU":
            status = "menu"
        if os.environ.get("ENTER_SPOOFERS") == "1":
            try:
                p.stdin.write(b"1\r\n"); p.stdin.flush(); log("[stdin] menu=1 spoofers")
            except Exception as e: log("[stdin err]", e)
            time.sleep(3)
            t = screen_text().replace("\r", "")
            log("[spoofers tail]")
            log(t[-2500:])
        # hold to see if VMProtect kills us later
        hold = float(os.environ.get("HOLD_SECONDS", "8"))
        log("[hold] keeping app alive", hold, "s")
        deadline = time.time() + hold
        while time.time() < deadline and p.poll() is None:
            time.sleep(0.2)
        if p.poll() is not None:
            log("[app] died during hold code", p.poll(), hex(p.poll() & 0xFFFFFFFF))
            status = "died:" + hex(p.poll() & 0xFFFFFFFF)
else:
    if needle in ("Welcome,", "MAIN MENU"):
        log("[wait] auto-sign-in detected; patched:", [hex(a) for a in patched_addrs])
        midx, mneedle, mtext = wait_for(["MAIN MENU"], 25, start=max(0, idx))
        log("[wait] mainmenu", repr(mneedle), "at", midx)
        if mneedle:
            status = "menu(auto)"
            if os.environ.get("ENTER_SPOOFERS") == "1":
                try:
                    p.stdin.write(b"1\r\n"); p.stdin.flush(); log("[stdin] menu=1 spoofers")
                except Exception as e: log("[stdin err]", e)
                time.sleep(3)
                t = screen_text().replace("\r", "")
                log("[spoofers tail]")
                log(t[-2500:])
            hold = float(os.environ.get("HOLD_SECONDS", "8"))
            log("[hold] keeping app alive", hold, "s")
            deadline = time.time() + hold
            while time.time() < deadline and p.poll() is None:
                time.sleep(0.2)
            if p.poll() is not None:
                log("[app] died during hold code", p.poll(), hex(p.poll() & 0xFFFFFFFF))
                status = "died:" + hex(p.poll() & 0xFFFFFFFF)
        else:
            status = "auto-no-menu"
    else:
        log("[wait] no login prompt; status stays", status)

# watch app for a few more seconds to see if it dies after patch
deadline = time.time() + 6
while time.time() < deadline and p.poll() is None:
    time.sleep(0.1)
if p.poll() is not None:
    log("[app] exit code", p.poll(), hex(p.poll() & 0xFFFFFFFF))
stop_evt.set()
if p.poll() is None:
    if "MAIN MENU" in screen_text():
        try: p.stdin.write(b"4\r\n"); p.stdin.flush(); log("[stdin] exit")
        except Exception: pass
        time.sleep(1.0)
    if p.poll() is None:
        p.terminate(); time.sleep(0.5)
log("[app] final poll", p.poll())

reg = winreg.OpenKey(winreg.HKEY_CURRENT_USER, keypath, 0, winreg.KEY_SET_VALUE)
for n, v in old.items():
    if v is None:
        try: winreg.DeleteValue(reg, n)
        except OSError: pass
    else:
        typ = winreg.REG_DWORD if isinstance(v, int) else winreg.REG_SZ
        winreg.SetValueEx(reg, n, 0, typ, v)
reg.Close()
try: srv.close(); pac_srv.shutdown()
except Exception: pass
log("[proxy] restored")

log("=== STATUS:", status, "===")
with req_lock:
    log("=== REQUESTS ===")
    for q in reqs: log(q)
t = screen_text().replace("\r", "")
log("=== TAIL ===")
log(t[-6000:])
logf.close()
