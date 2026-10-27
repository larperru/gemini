import os, sys, time, ctypes, subprocess, threading, re
from ctypes import wintypes

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
APP = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
OUT = r"C:\Users\celnik__\Desktop\New folder (4)\_work\validator_scan.txt"
WAIT = float(os.environ.get("WAIT", "6"))

k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                  ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.CloseHandle.argtypes = [wintypes.HANDLE]

class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("PartitionId", wintypes.WORD),
                ("alignment1", wintypes.WORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("alignment2", wintypes.DWORD)]

k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                               ctypes.POINTER(MBI), ctypes.c_size_t]

NEEDLES = [
    "bad key or username",
    "invalid key or credentials",
    "License key",
    "Username",
    "TLS pin mismatch",
    "Too many attempts",
    "VT-",
    "a-z 0-9",
]
NEEDLE_BYTES = []
for n in NEEDLES:
    NEEDLE_BYTES.append((n, n.encode("utf-16le")))
    NEEDLE_BYTES.append((n + " [ascii]", n.encode()))

env = dict(os.environ)
env["__COMPAT_LAYER"] = "RunAsInvoker"
p = subprocess.Popen([APP], cwd=os.path.dirname(APP), env=env,
                     stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
print("[app] pid", p.pid, flush=True)
time.sleep(WAIT)
send = os.environ.get("SEND", "")
if send:
    user, _, key = send.partition("|")
    try:
        p.stdin.write((user + "\r\n").encode()); p.stdin.flush()
        time.sleep(0.5)
        p.stdin.write((key + "\r\n").encode()); p.stdin.flush()
        print("[send] credentials sent", flush=True)
    except Exception as e:
        print("[send err]", repr(e), flush=True)
    time.sleep(float(os.environ.get("AFTER_SEND", "1.0")))

h = k32.OpenProcess(0x1F0FFF, False, p.pid)
if not h:
    print("[!] OpenProcess failed", ctypes.get_last_error(), flush=True)
    p.terminate()
    sys.exit(1)

out = open(OUT, "w", encoding="utf-8")
out.write("pid %d\n" % p.pid)
addr = 0
hits = {name: [] for name, _ in NEEDLE_BYTES}
regions = 0
read_bytes = 0
max_addr = 0x7FFFFFFFFFFF
buf = ctypes.create_string_buffer(0x100000)
got = ctypes.c_size_t()
while addr < max_addr:
    mbi = MBI()
    if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                              ctypes.sizeof(mbi)):
        break
    rbase = int(mbi.BaseAddress or 0)
    rsize = int(mbi.RegionSize or 0)
    if not rsize:
        break
    rend = rbase + rsize
    readable = (mbi.State == 0x1000 and not (mbi.Protect & 0x100)
                and (mbi.Protect & 0xFF) in (0x02, 0x04, 0x08, 0x20, 0x40, 0x80))
    if readable and rsize <= 0x40000000:
        regions += 1
        off = rbase
        while off < rend:
            n = min(len(buf), rend - off)
            if k32.ReadProcessMemory(h, ctypes.c_void_p(off), buf, n,
                                     ctypes.byref(got)) and got.value:
                data = buf.raw[:got.value]
                read_bytes += got.value
                for name, nb in NEEDLE_BYTES:
                    pos = 0
                    while True:
                        i = data.find(nb, pos)
                        if i < 0:
                            break
                        hits[name].append(off + i)
                        pos = i + 1
                        if len(hits[name]) >= 200:
                            break
            off += n
    addr = rend

print("[scan] regions", regions, "bytes", read_bytes, flush=True)
for name, addrs in hits.items():
    addrs = sorted(set(addrs))
    print("[hit] %-40s %d %s" % (name, len(addrs),
          " ".join("%#x" % a for a in addrs[:20])), flush=True)
    out.write("[hit] %-40s %d\n" % (name, len(addrs)))
    for a in addrs[:100]:
        out.write("  %#x\n" % a)

# Dump UTF-16 strings around the first "bad key" hit and first "invalid key" hit.
def region_info(a):
    mbi = MBI()
    if k32.VirtualQueryEx(h, ctypes.c_void_p(a), ctypes.byref(mbi),
                          ctypes.sizeof(mbi)):
        return ("base=%#x size=%#x state=%#x prot=%#x type=%#x" %
                (int(mbi.BaseAddress or 0), int(mbi.RegionSize or 0),
                 int(mbi.State), int(mbi.Protect), int(mbi.Type)))
    return "region unknown"


def dump_context(tag, center, before=0x400, after=0x800):
    lo = max(0, center - before)
    n = before + after
    b = ctypes.create_string_buffer(n)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(lo), b, n,
                                 ctypes.byref(got)) or not got.value:
        out.write("\n== %s %#x unreadable ==\n" % (tag, center))
        return
    data = b.raw[:got.value]
    out.write("\n== %s %#x %s ==\n" % (tag, center, region_info(center)))
    # printable ascii-ish strings
    for enc in ("utf-16le", "latin1"):
        out.write("-- %s strings --\n" % enc)
        text = data.decode(enc, "replace")
        for m in re.finditer(r"[ -~]{6,}", text):
            s = m.group(0)
            if any(x in s for x in ("key", "Username", "License", "VT-", "bad", "invalid", "3-20", "TLS", "pin", "attempt")):
                out.write("  +%#x: %s\n" % (m.start(), s[:300]))
    out.write("-- hex --\n")
    for i in range(0, len(data), 32):
        out.write("%#010x  %s  %s\n" % (lo + i,
                  data[i:i+16].hex(" "),
                  "".join(chr(c) if 32 <= c < 127 else "." for c in data[i:i+16])))
    out.write("-- utf16 dump --\n")
    out.write(re.sub(r"[^\x20-\x7e\r\n\t]", ".", text)[:4000] + "\n")

for key in ("bad key or username", "invalid key or credentials",
            "License key", "Too many attempts", "a-z 0-9"):
    addrs = sorted(set(hits.get(key, []) + hits.get(key + " [ascii]", [])))
    for a in addrs[:5]:
        dump_context(key, a)

out.close()
k32.CloseHandle(h)
try:
    p.stdin.close()
except Exception:
    pass
try:
    p.terminate(); p.wait(timeout=5)
except Exception:
    pass
print("[done]", OUT, flush=True)
