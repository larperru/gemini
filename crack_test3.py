import os, sys, ssl, socket, threading, time, json, subprocess, tempfile, shutil, re, importlib.util, ctypes, hashlib
from ctypes import wintypes

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
CRACK_PY = r"C:\Users\celnik__\Downloads\crack.py"
spec = importlib.util.spec_from_file_location("vtcrack", CRACK_PY)
vtc = importlib.util.module_from_spec(spec); spec.loader.exec_module(vtc)

EXE = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
WORK = r"C:\Users\celnik__\Desktop\New folder (4)\_work"
LOG = os.path.join(WORK, "crack_test3.log")
RAWOUT = os.path.join(WORK, "dump", "crack_test3_raw.txt")
PROXY_PORT = 8443
PAC_PORT = 8444
PIN_OFFSETS = [0x10C420, 0x10C440]
REAL_PIN = bytes.fromhex("b3e8bc059cf27952ce73481e81c9019581403d0d42232d9ad53c16a4eedafe8d")
REAL_PIN_HEX = REAL_PIN.hex().encode()
REAL_PIN_HEX_W = REAL_PIN.hex().upper().encode("utf-16le")

from cryptography import x509
from cryptography.hazmat.primitives import serialization
fake_der = ssl.PEM_cert_to_DER_cert(vtc.CRT_PEM)
fake_spki = x509.load_der_x509_certificate(fake_der).public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
FAKE_PIN = hashlib.sha256(fake_spki).digest()
FAKE_PIN_HEX = FAKE_PIN.hex().encode()
FAKE_PIN_HEX_W = FAKE_PIN.hex().upper().encode("utf-16le")
assert len(FAKE_PIN) == 32

logf = open(LOG, "w", encoding="utf-8", buffering=1)
t0 = time.time()
def log(*a):
    s = " ".join(str(x) for x in a)
    print("[%7.3f] %s" % (time.time() - t0, s), flush=True)
    logf.write("[%7.3f] %s\n" % (time.time() - t0, s))

# ---------- fake CA / server cert ----------
tmp = tempfile.mkdtemp(prefix="vt_crack3_")
ca, crt, key = vtc.write_pems(tmp)
r = subprocess.run(["certutil", "-user", "-addstore", "-f", "Root", ca], capture_output=True, text=True, errors="ignore")
log("[ca] addstore rc", r.returncode)

# ---------- PAC proxy ----------
PROXY_HOST = "vanishtrace.authvt.workers.dev"
PAC = ("function FindProxyForURL(url, host) {\n"
       f'  if (host === "{PROXY_HOST}") return "PROXY 127.0.0.1:{PROXY_PORT}";\n'
       '  return "DIRECT";\n}\n')

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class PacHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        data = PAC.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)
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

ctxssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctxssl.load_cert_chain(crt, key)
reqs = []
req_lock = threading.Lock()

def serve_conn(c):
    try:
        c.settimeout(15)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            d = c.recv(4096)
            if not d: return
            buf += d
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
        first = head.splitlines()[0] if head else ""
        c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        t = ctxssl.wrap_socket(c, server_side=True)
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            d = t.recv(4096)
            if not d: return
            data += d
        hdr = data.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
        lines = hdr.splitlines(); reqline = lines[0] if lines else ""
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
        if clean.endswith("/api/hash"):
            obj = {"sha256": None}
        elif clean.endswith("/api/nonce"):
            obj = {"nonce": "a" * 32}
        else:
            obj = {"ok": True, "username": user, "expiresAt": vtc.EXPIRES_MS}
        out = json.dumps(obj, separators=(",", ":")).encode()
        t.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
                  str(len(out)).encode() + b"\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n" + out)
        with req_lock:
            reqs.append((method, path, body[:500].decode("utf-8", "replace"), obj))
        log("[request]", method, path, "body=", body[:300].decode("utf-8", "replace"))
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

# ---------- memory tools ----------
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
    finally:
        k32.CloseHandle(snap)
    return None, None

patched_lock = threading.Lock()
patched = {}          # addr -> (time, regiontype, prot)
reverts = []
first_seen = {}
patch_count = [0]
stop_evt = threading.Event()

def read_mem(h, addr, n):
    buf = ctypes.create_string_buffer(n)
    rd = ctypes.c_size_t()
    if k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(rd)) and rd.value == n:
        return buf.raw
    return None

def write_mem(h, addr, data, prot):
    oldp = wintypes.DWORD()
    if not k32.VirtualProtectEx(h, ctypes.c_void_p(addr), len(data), 0x04, ctypes.byref(oldp)):
        return False, ctypes.get_last_error()
    w = ctypes.c_size_t()
    ok = bool(k32.WriteProcessMemory(h, ctypes.c_void_p(addr), data, len(data), ctypes.byref(w)) and w.value == len(data))
    k32.VirtualProtectEx(h, ctypes.c_void_p(addr), len(data), oldp.value, ctypes.byref(oldp))
    return ok, 0

def patch_at(h, addr, rtype, prot, tag):
    now = time.time() - t0
    old = read_mem(h, addr, 32)
    if old is None:
        return False
    if old == FAKE_PIN:
        return False
    if old != REAL_PIN:
        # maybe hex text variant
        return False
    ok, err = write_mem(h, addr, FAKE_PIN, prot)
    if ok:
        with patched_lock:
            first = addr not in patched
            if not first:
                reverts.append((now, addr))
            patched[addr] = (now, rtype, prot, tag)
            patch_count[0] += 1
        log("[pin] patched %s addr=%#x type=%#x prot=%#x (%s)" % ("REVERT" if not first else "new", addr, rtype, prot, tag))
        # read back
        chk = read_mem(h, addr, 32)
        if chk != FAKE_PIN:
            log("[pin] WARNING readback mismatch addr=%#x got=%s" % (addr, (chk or b"").hex()))
        return True
    else:
        log("[pin] write failed addr=%#x err=%d" % (addr, err))
        return False

def region_scan(h, base, size, tag_prefix, only_private=False, stop=None, max_seconds=None):
    addr = base
    end = base + size
    buf = ctypes.create_string_buffer(0x200000)
    rd = ctypes.c_size_t()
    found = 0
    while addr < end:
        if stop is not None and stop.is_set(): break
        mbi = MBI()
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        rbase = int(mbi.BaseAddress or 0); rsize = int(mbi.RegionSize or 0)
        if not rsize: break
        rend = rbase + rsize
        if rbase < base: rbase = base
        if rend > end: rend = end
        prot = mbi.Protect & 0xFF
        readable = mbi.State == 0x1000 and not (mbi.Protect & 0x100) and prot in (0x02, 0x04, 0x08, 0x20, 0x40, 0x80)
        if readable and (not only_private or mbi.Type == 0x20000):
            off = rbase
            while off < rend:
                n = min(len(buf), rend - off)
                if k32.ReadProcessMemory(h, ctypes.c_void_p(off), buf, n, ctypes.byref(rd)) and rd.value:
                    data = buf.raw[:rd.value]
                    pos = 0
                    while True:
                        i = data.find(REAL_PIN, pos)
                        if i < 0: break
                        va = off + i
                        first_seen.setdefault(va, time.time() - t0)
                        if patch_at(h, va, mbi.Type, mbi.Protect, tag_prefix):
                            found += 1
                        pos = i + 1
                off += n
        addr = rbase + rsize
    return found

def patcher(pid):
    h = k32.OpenProcess(0x1F0FFF, False, pid)
    if not h:
        log("[pin] OpenProcess failed", ctypes.get_last_error()); return
    base = None
    for _ in range(500):
        base, msize = module_info(pid)
        if base: break
        time.sleep(0.01)
    log("[pin] module base", hex(base or 0), "size", hex(msize or 0))
    if not base:
        return
    last_full = 0.0
    last_mod = 0.0
    while not stop_evt.is_set():
        now = time.time()
        # 1) static offsets, tight loop
        for off in PIN_OFFSETS:
            va = base + off
            cur = read_mem(h, va, 32)
            if cur == REAL_PIN:
                first_seen.setdefault(va, now - t0)
                patch_at(h, va, 0x20000, 0x04, "static")
        # 2) whole image scan ~4x/sec
        if now - last_mod > 0.25:
            region_scan(h, base, msize, "image", only_private=False)
            last_mod = now
        # 3) all private committed memory (heap/stacks) ~1x/sec
        if now - last_full > 0.75:
            region_scan(h, 0, 0x7FFFFFFFFFFF, "private", only_private=True)
            last_full = now
        time.sleep(0.005)
    log("[pin] patcher done; total writes=%d unique=%d reverts=%d" % (patch_count[0], len(patched), len(reverts)))
    k32.CloseHandle(h)

# ---------- prompt-aware stdin ----------
ANSI_CSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]")
ANSI_OSC = re.compile(rb"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
screen_lock = threading.Lock()
screen = bytearray()
reader_done = threading.Event()

def reader(pipe):
    global screen
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
                if len(screen) > 400000:
                    del screen[:len(screen) - 300000]
    except Exception as e:
        log("[reader err]", repr(e))
    finally:
        rawf.close(); reader_done.set(); log("[reader] EOF")

def screen_text():
    with screen_lock:
        return bytes(screen).decode("utf-8", "replace")

def wait_for(needles, timeout, start=0):
    """wait until any needle appears in screen text after index start; returns (idx, needle, fulltext)"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        t = screen_text()
        for n in needles:
            i = t.find(n, start)
            if i >= 0:
                return i, n, t
        if reader_done.is_set():
            break
        time.sleep(0.02)
    return -1, None, screen_text()

# ---------- run ----------
env = dict(os.environ); env["__COMPAT_LAYER"] = "RunAsInvoker"
os.makedirs(os.path.dirname(RAWOUT), exist_ok=True)
p = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
log("[app] pid", p.pid)
th_reader = threading.Thread(target=reader, args=(p.stdout,), daemon=True); th_reader.start()
th_pin = threading.Thread(target=patcher, args=(p.pid,), daemon=True); th_pin.start()

status = "timeout"
# wait for login prompt
idx, needle, text = wait_for(["Username:", "MAIN MENU", "Welcome,"], 45)
log("[wait] first trigger", repr(needle), "at", idx)
if needle == "Username:":
    # make sure pin patch already present
    with patched_lock:
        np = len(patched)
    log("[state] pins patched before login:", np, [hex(a) for a in list(patched)[:8]])
    time.sleep(0.3)
    try:
        p.stdin.write(b"tester\r\n"); p.stdin.flush(); log("[stdin] username sent")
    except Exception as e: log("[stdin err]", e)
    time.sleep(0.7)
    try:
        p.stdin.write(b"VT-ABCDEF-GHJKLM-NPQRST\r\n"); p.stdin.flush(); log("[stdin] key sent")
    except Exception as e: log("[stdin err]", e)

# wait for result
idx2, needle2, text2 = wait_for(["Welcome,", "MAIN MENU", "TLS pin mismatch", "bad key or username", "invalid", "expired"],
                                40, start=max(0, idx if idx > 0 else 0))
log("[wait] result trigger", repr(needle2), "at", idx2)
if needle2 and ("Welcome," in needle2 or "MAIN MENU" in needle2):
    status = "success"
elif needle2:
    status = "fail:" + needle2
    # if we landed on a retry prompt, try once more with a fresh username
    tail = text2[idx2:idx2+400].replace("\n", " ")
    log("[tail around result]", tail)
    # detect if still at username prompt; send again
    if "Username:" in text2[idx2:]:
        try:
            p.stdin.write(b"tester\r\n"); p.stdin.flush(); log("[stdin] retry username")
            time.sleep(0.5)
            p.stdin.write(b"VT-ABCDEF-GHJKLM-NPQRST\r\n"); p.stdin.flush(); log("[stdin] retry key")
        except Exception as e: log("[stdin err]", e)
        idx3, needle3, text3 = wait_for(["Welcome,", "MAIN MENU", "TLS pin mismatch", "bad key or username"], 25, start=len(text2))
        log("[wait] retry trigger", repr(needle3), "at", idx3)
        if needle3 and ("Welcome," in needle3 or "MAIN MENU" in needle3):
            status = "success"

# give UI a moment then exit cleanly
time.sleep(1.0)
try:
    if p.poll() is None:
        # if at main menu, exit with 4
        if "MAIN MENU" in screen_text():
            p.stdin.write(b"4\r\n"); p.stdin.flush(); log("[stdin] sent 4 (exit)")
            time.sleep(1.0)
except Exception as e: log("[stdin err]", e)
stop_evt.set(); th_pin.join(timeout=3)
if p.poll() is None:
    p.terminate(); time.sleep(0.5)
log("[app] poll", p.poll())

# restore proxy
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
log("[proxy] restored", old)

# summary
log("=== STATUS:", status, "===")
with req_lock:
    log("=== REQUESTS ===")
    for q in reqs: log(q)
log("=== PINS ===")
with patched_lock:
    for a, info in sorted(patched.items()):
        log("  %#x first=%s type=%#x prot=%#x tag=%s" % (a, ("%.3f" % info[0]), info[1], info[2], info[3]))
    log("  reverts:", reverts)
log("=== TAIL ===")
t = screen_text()
t = re.sub(r"\r", "", t)
log(t[-8000:])
logf.close()
