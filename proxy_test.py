import os, sys, ssl, socket, threading, time, json, subprocess, tempfile, shutil, re, importlib.util

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CRACK_PY = r"C:\Users\celnik__\Downloads\crack.py"
spec = importlib.util.spec_from_file_location("vtcrack", CRACK_PY)
vtc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vtc)

EXE = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
WORK = r"C:\Users\celnik__\Desktop\New folder (4)\_work"
LOG = os.path.join(WORK, "proxy_test.log")
PROXY_PORT = 8443
HOST = "vanishtrace.authvt.workers.dev"

logf = open(LOG, "w", encoding="utf-8", buffering=1)
def log(*a):
    s = " ".join(str(x) for x in a)
    print(s, flush=True)
    logf.write(s + "\n")

tmp = tempfile.mkdtemp(prefix="vt_proxy_")
ca, crt, key = vtc.write_pems(tmp)

# trust CA for current user only (no admin)
r = subprocess.run(["certutil", "-user", "-addstore", "-f", "Root", ca], capture_output=True, text=True, errors="ignore")
log("[ca] addstore rc", r.returncode, r.stdout.strip().splitlines()[-1:] if r.stdout else "")

# proxy settings (backup)
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
        first = head.splitlines()[0] if head else ""
        log("[connect]", first)
        c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        t = ctx.wrap_socket(c, server_side=True)
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            d = t.recv(4096)
            if not d: return
            data += d
        hdr = data.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
        lines = hdr.splitlines()
        reqline = lines[0] if lines else ""
        hdrs = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs[k.strip().lower()] = v.strip()
        clen = int(hdrs.get("content-length") or 0)
        body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
        while len(body) < clen:
            d = t.recv(4096)
            if not d: break
            body += d
        parts = reqline.split(" ")
        method = parts[0] if parts else "?"
        path = parts[1] if len(parts) > 1 else "/"
        log("[request]", method, path, "body=", body[:400].decode("utf-8", "replace"))
        try:
            req = json.loads(body) if body else {}
        except Exception:
            req = {}
        user = req.get("username") or vtc.DEFAULT_USER
        if path.split("?")[0].endswith("/api/hash"):
            obj = {"sha256": None}
        elif path.split("?")[0].endswith("/api/nonce"):
            obj = {"nonce": "a" * 32}
        else:
            obj = {"ok": True, "username": user, "expiresAt": vtc.EXPIRES_MS}
        out = json.dumps(obj, separators=(",", ":")).encode()
        resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: " + str(len(out)).encode() + b"\r\n"
                b"Connection: close\r\nCache-Control: no-store\r\n\r\n" + out)
        t.sendall(resp)
        reqs.append((method, path, obj))
        try: t.close()
        except Exception: pass
    except Exception as e:
        log("[conn err]", repr(e))
    finally:
        try: c.close()
        except Exception: pass

def acceptor(srv):
    while True:
        try:
            c, a = srv.accept()
        except OSError:
            return
        threading.Thread(target=serve_conn, args=(c,), daemon=True).start()

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PROXY_PORT))
srv.listen(16)
threading.Thread(target=acceptor, args=(srv,), daemon=True).start()
log("[proxy] listening on", PROXY_PORT)

# back up session then run
cache = os.path.join(os.environ["LOCALAPPDATA"], r"Microsoft\Windows\Caches")
bkp = os.path.join(WORK, "session_backup.db")
for fn in os.listdir(cache):
    if fn.startswith("session_") and fn.endswith(".db"):
        shutil.copy2(os.path.join(cache, fn), bkp)
        log("[session] backed up", fn, "->", bkp)

env = dict(os.environ); env["__COMPAT_LAYER"] = "RunAsInvoker"
outpath = os.path.join(WORK, "dump", "proxy_run.txt")
os.makedirs(os.path.dirname(outpath), exist_ok=True)
f = open(outpath, "wb")
p = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=f, stderr=subprocess.STDOUT, env=env)
log("[app] pid", p.pid)
time.sleep(12)
if p.poll() is None:
    log("[app] still alive after 12s")
    try:
        p.stdin.write(b"4\r\n"); p.stdin.flush()
    except Exception as e: log("stdin", e)
    time.sleep(2)
if p.poll() is None:
    p.terminate(); time.sleep(1)
log("[app] poll", p.poll())
f.close()

# restore
reg = winreg.OpenKey(winreg.HKEY_CURRENT_USER, keypath, 0, winreg.KEY_SET_VALUE)
for n, v in old.items():
    if v is None:
        try: winreg.DeleteValue(reg, n)
        except OSError: pass
    else:
        typ = winreg.REG_DWORD if isinstance(v, int) else winreg.REG_SZ
        winreg.SetValueEx(reg, n, 0, typ, v)
reg.Close()
log("[proxy] restored", old)

try: srv.close()
except Exception: pass

data = open(outpath, "rb").read().decode("utf-8", "replace")
t = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", data)
t = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", t).replace("\x1b", "")
log("=== TAIL ===")
log(t[-5000:])
log("=== REQUESTS ===")
for r_ in reqs:
    log(r_)
log("[done] tmp", tmp)
logf.close()
