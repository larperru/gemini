import os, sys, ssl, socket, threading, time, json, subprocess, tempfile, shutil, re, importlib.util, ctypes
from ctypes import wintypes

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
CRACK_PY = r"C:\Users\celnik__\Downloads\crack.py"
spec = importlib.util.spec_from_file_location("vtcrack", CRACK_PY)
vtc = importlib.util.module_from_spec(spec); spec.loader.exec_module(vtc)

EXE = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
WORK = r"C:\Users\celnik__\Desktop\New folder (4)\_work"
LOG = os.path.join(WORK, "proxy_pin_test.log")
PROXY_PORT = 8443
HOST = "vanishtrace.authvt.workers.dev"
REAL_PIN = bytes.fromhex("b3e8bc059cf27952ce73481e81c9019581403d0d42232d9ad53c16a4eedafe8d")

from cryptography import x509
from cryptography.hazmat.primitives import serialization
import hashlib
fake_der = ssl.PEM_cert_to_DER_cert(vtc.CRT_PEM)
fake_spki = x509.load_der_x509_certificate(fake_der).public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
FAKE_PIN = hashlib.sha256(fake_spki).digest()
assert len(FAKE_PIN) == 32

logf = open(LOG, "w", encoding="utf-8", buffering=1)
def log(*a):
    s = " ".join(str(x) for x in a); print(s, flush=True); logf.write(s + "\n")

tmp = tempfile.mkdtemp(prefix="vt_pin_")
ca, crt, key = vtc.write_pems(tmp)
r = subprocess.run(["certutil", "-user", "-addstore", "-f", "Root", ca], capture_output=True, text=True, errors="ignore")
log("[ca] addstore rc", r.returncode)

import winreg
keypath = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg = winreg.OpenKey(winreg.HKEY_CURRENT_USER, keypath, 0, winreg.KEY_READ)
def getv(n, d=None):
    try: return winreg.QueryValueEx(reg, n)[0]
    except OSError: return d
old = {n: getv(n) for n in ("ProxyEnable", "ProxyServer", "ProxyOverride")}
reg.Close()
log("[proxy] old", old)
reg = winreg.OpenKey(winreg.HKEY_CURRENT_USER, keypath, 0, winreg.KEY_SET_VALUE)
winreg.SetValueEx(reg, "ProxyEnable", 0, winreg.REG_DWORD, 1)
winreg.SetValueEx(reg, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{PROXY_PORT}")
winreg.SetValueEx(reg, "ProxyOverride", 0, winreg.REG_SZ, "*.local")
reg.Close()

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(crt, key)
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
        log("[connect]", head.splitlines()[0] if head else "")
        c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        t = ctx.wrap_socket(c, server_side=True)
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
        clean_path = path.split("?")[0]
        if clean_path.endswith("/api/hash"):
            obj = {"sha256": None}
        elif clean_path.endswith("/api/nonce"):
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

# --- memory patcher ---
k32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualProtectEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
k32.CloseHandle.argtypes = [wintypes.HANDLE]

class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p), ("SizeOfImage", wintypes.DWORD), ("EntryPoint", ctypes.c_void_p)]
psapi.GetModuleInformation.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MODULEINFO), wintypes.DWORD]

def patcher(pid, stop_evt, results):
    h = k32.OpenProcess(0x1F0FFF, False, pid)
    if not h:
        results.append(("openfail", ctypes.get_last_error())); return
    results.append(("opened", pid))
    try:
        base = None; size = None
        for _ in range(100):
            mods = (ctypes.c_void_p * 1024)(); needed = wintypes.DWORD()
            if psapi.EnumProcessModules(h, mods, ctypes.sizeof(mods), ctypes.byref(needed)):
                mi = MODULEINFO()
                if psapi.GetModuleInformation(h, mods[0], ctypes.byref(mi), ctypes.sizeof(mi)):
                    base = mi.lpBaseOfDll; size = mi.SizeOfImage; break
            time.sleep(0.02)
        if not base:
            results.append(("nobase",)); return
        results.append(("base", hex(base), hex(size)))
        buf = ctypes.create_string_buffer(0x200000)
        rd = ctypes.c_size_t()
        patched = 0
        t0 = time.time()
        while time.time() - t0 < 15 and not stop_evt.is_set():
            found_any = False
            off = 0
            while off < size:
                n = min(len(buf), size - off)
                addr = base + off
                if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(rd)) or rd.value == 0:
                    off += n; continue
                data = buf.raw[:rd.value]
                pos = 0
                while True:
                    i = data.find(REAL_PIN, pos)
                    if i < 0: break
                    found_any = True
                    va = addr + i
                    oldp = wintypes.DWORD()
                    if k32.VirtualProtectEx(h, ctypes.c_void_p(va), 32, 0x04, ctypes.byref(oldp)):
                        w = ctypes.c_size_t()
                        if k32.WriteProcessMemory(h, ctypes.c_void_p(va), FAKE_PIN, 32, ctypes.byref(w)) and w.value == 32:
                            patched += 1
                            results.append(("patched", hex(va), "prot", hex(oldp.value)))
                        k32.VirtualProtectEx(h, ctypes.c_void_p(va), 32, oldp.value, ctypes.byref(oldp))
                    else:
                        results.append(("protfail", hex(va), ctypes.get_last_error()))
                    pos = i + 1
                off += max(1, rd.value - 31)
            if patched and not found_any:
                break
            time.sleep(0.05)
        results.append(("patched_total", patched))
    finally:
        k32.CloseHandle(h)

cache = os.path.join(os.environ["LOCALAPPDATA"], r"Microsoft\Windows\Caches")
bkp = os.path.join(WORK, "session_backup.db")
for fn in os.listdir(cache):
    if fn.startswith("session_") and fn.endswith(".db"):
        shutil.copy2(os.path.join(cache, fn), bkp)

env = dict(os.environ); env["__COMPAT_LAYER"] = "RunAsInvoker"
outpath = os.path.join(WORK, "dump", "proxy_pin_run.txt")
os.makedirs(os.path.dirname(outpath), exist_ok=True)
f = open(outpath, "wb")
p = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=f, stderr=subprocess.STDOUT, env=env)
log("[app] pid", p.pid)
stop_evt = threading.Event(); results = []
th = threading.Thread(target=patcher, args=(p.pid, stop_evt, results), daemon=True); th.start()
time.sleep(14)
stop_evt.set(); th.join(timeout=5)
log("[patcher]", results)
if p.poll() is None:
    log("[app] alive -> sending 4")
    try: p.stdin.write(b"4\r\n"); p.stdin.flush()
    except Exception as e: log("stdin", e)
    time.sleep(2)
if p.poll() is None:
    p.terminate(); time.sleep(1)
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
try: srv.close()
except Exception: pass
log("[proxy] restored", old)

data = open(outpath, "rb").read().decode("utf-8", "replace")
t = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", data)
t = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", t).replace("\x1b", "")
log("=== TAIL ===")
log(t[-4500:])
log("=== REQUESTS ===")
for r_ in reqs: log(r_)
logf.close()
