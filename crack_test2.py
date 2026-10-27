import os, sys, ssl, socket, threading, time, json, subprocess, tempfile, shutil, re, importlib.util, ctypes, hashlib
from ctypes import wintypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
CRACK_PY = r"C:\Users\celnik__\Downloads\crack.py"
spec = importlib.util.spec_from_file_location("vtcrack", CRACK_PY)
vtc = importlib.util.module_from_spec(spec); spec.loader.exec_module(vtc)

EXE = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
WORK = r"C:\Users\celnik__\Desktop\New folder (4)\_work"
LOG = os.path.join(WORK, "crack_test2.log")
PROXY_PORT = 8443
PAC_PORT = 8444
PIN_OFFSETS = [0x10C420, 0x10C440]

from cryptography import x509
from cryptography.hazmat.primitives import serialization
fake_der = ssl.PEM_cert_to_DER_cert(vtc.CRT_PEM)
fake_spki = x509.load_der_x509_certificate(fake_der).public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
FAKE_PIN = hashlib.sha256(fake_spki).digest()

logf = open(LOG, "w", encoding="utf-8", buffering=1)
def log(*a):
    s = " ".join(str(x) for x in a); print(s, flush=True); logf.write(s + "\n")

tmp = tempfile.mkdtemp(prefix="vt_crack2_")
ca, crt, key = vtc.write_pems(tmp)
r = subprocess.run(["certutil", "-user", "-addstore", "-f", "Root", ca], capture_output=True, text=True, errors="ignore")
log("[ca] addstore rc", r.returncode)

# PAC so only our host goes through the proxy
PAC = f'''function FindProxyForURL(url, host) {{
  if (host === "vanishtrace.authvt.workers.dev") return "PROXY 127.0.0.1:{PROXY_PORT}";
  if (host === "discord.gg" || host === "www.discord.gg") return "PROXY 127.0.0.1:{PROXY_PORT}";
  return "DIRECT";
}}'''
class PacHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        data = PAC.encode()
        self.send_response(200); self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
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

ctxssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctxssl.load_cert_chain(crt, key)
reqs = []

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
        log("[connect]", first)
        if "discord" in first.lower():
            c.sendall(b"HTTP/1.1 302 Found\r\nLocation: https://discord.gg/vruTdQMGNe\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
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
        t.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(out)).encode() +
                  b"\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n" + out)
        reqs.append((method, path, obj))
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

# --- targeted pin patcher ---
k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualProtectEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
k32.CloseHandle.argtypes = [wintypes.HANDLE]

class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                ("GlblcntUsage", wintypes.DWORD), ("ProccntUsage", wintypes.DWORD), ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", wintypes.DWORD), ("hModule", ctypes.c_void_p), ("szModule", wintypes.WCHAR*256),
                ("szExePath", wintypes.WCHAR*260)]

def module_base(pid):
    k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    k32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    snap = k32.CreateToolhelp32Snapshot(8 | 16, pid)
    if not snap or snap == ctypes.c_void_p(-1).value: return None
    me = MODULEENTRY32W(); me.dwSize = ctypes.sizeof(me)
    try:
        ok = k32.Module32FirstW(snap, ctypes.byref(me))
        while ok:
            if me.szModule.lower() == "vanishtrace.exe":
                return int(me.modBaseAddr or 0)
            ok = k32.Module32NextW(snap, ctypes.byref(me))
    finally:
        k32.CloseHandle(snap)
    return None

def patcher(pid, stop_evt, results):
    h = k32.OpenProcess(0x1F0FFF, False, pid)
    if not h:
        results.append(("openfail", ctypes.get_last_error())); return
    try:
        base = None
        for _ in range(500):
            base = module_base(pid)
            if base: break
            time.sleep(0.01)
        results.append(("base", hex(base or 0)))
        if not base: return
        done = set()
        t0 = time.time()
        while time.time() - t0 < 20 and not stop_evt.is_set():
            for off in PIN_OFFSETS:
                va = base + off
                readbuf = ctypes.create_string_buffer(32); rd = ctypes.c_size_t()
                if not k32.ReadProcessMemory(h, ctypes.c_void_p(va), readbuf, 32, ctypes.byref(rd)) or rd.value != 32:
                    continue
                if readbuf.raw == FAKE_PIN:
                    done.add(off); continue
                oldp = wintypes.DWORD()
                if k32.VirtualProtectEx(h, ctypes.c_void_p(va), 32, 0x04, ctypes.byref(oldp)):
                    w = ctypes.c_size_t()
                    ok = k32.WriteProcessMemory(h, ctypes.c_void_p(va), FAKE_PIN, 32, ctypes.byref(w)) and w.value == 32
                    k32.VirtualProtectEx(h, ctypes.c_void_p(va), 32, oldp.value, ctypes.byref(oldp))
                    if ok:
                        done.add(off); results.append(("patched", hex(va)))
            if len(done) == len(PIN_OFFSETS):
                # verify
                good = 0
                for off in PIN_OFFSETS:
                    b = ctypes.create_string_buffer(32); rd = ctypes.c_size_t()
                    if k32.ReadProcessMemory(h, ctypes.c_void_p(base + off), b, 32, ctypes.byref(rd)) and b.raw == FAKE_PIN:
                        good += 1
                if good == len(PIN_OFFSETS):
                    results.append(("verified", good)); return
            time.sleep(0.02)
        results.append(("timeout", sorted(done)))
    finally:
        k32.CloseHandle(h)

# clean our bogus empty session
cache = os.path.join(os.environ["LOCALAPPDATA"], r"Microsoft\Windows\Caches")
for fn in os.listdir(cache):
    if fn.startswith("session_") and fn.endswith(".db"):
        pth = os.path.join(cache, fn)
        if os.path.getsize(pth) == 0:
            try: os.remove(pth)
            except Exception as e: log("session remove", e)
        else:
            log("[session] existing non-empty", fn, os.path.getsize(pth))

env = dict(os.environ); env["__COMPAT_LAYER"] = "RunAsInvoker"
outpath = os.path.join(WORK, "dump", "crack_test2_run.txt")
os.makedirs(os.path.dirname(outpath), exist_ok=True)
f = open(outpath, "wb")
p = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=f, stderr=subprocess.STDOUT, env=env)
log("[app] pid", p.pid)
stop_evt = threading.Event(); results = []
th = threading.Thread(target=patcher, args=(p.pid, stop_evt, results), daemon=True); th.start()

# feed login credentials early; app consumes as needed
time.sleep(6)
try:
    p.stdin.write(b"tester\r\nVT-ABCDEF-GHJKLM-NPQRST\r\nn\r\n")
    p.stdin.flush()
    log("[stdin] credentials sent")
except Exception as e:
    log("stdin err", e)
time.sleep(8)
try:
    p.stdin.write(b"4\r\n"); p.stdin.flush()
    log("[stdin] sent 4")
except Exception as e:
    pass
time.sleep(3)
stop_evt.set(); th.join(timeout=5)
log("[patcher]", results)
if p.poll() is None:
    p.terminate(); time.sleep(0.5)
log("[app] poll", p.poll())
f.close()

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

data = open(outpath, "rb").read().decode("utf-8", "replace")
t = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", data)
t = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", t).replace("\x1b", "")
log("=== TAIL ===")
log(t[-6000:])
log("=== REQUESTS ===")
for r_ in reqs: log(r_)
logf.close()
