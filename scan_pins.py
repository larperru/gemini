import os, sys, ctypes, time, subprocess, struct, re
from ctypes import wintypes
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

EXE = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
WORK = r"C:\Users\celnik__\Desktop\New folder (4)\_work"
OUT = os.path.join(WORK, "dump", "scan_run.txt")

PINS = {
 "leaf": bytes.fromhex("b3e8bc059cf27952ce73481e81c9019581403d0d42232d9ad53c16a4eedafe8d"),
 "ye1": bytes.fromhex("6ebcefb4210b088654a38b03fea3d7d1c711b4fb1ddc363a45f9b1a4e53da01e"),
 "rootye": bytes.fromhex("b0292ae545978e0fbb98abbd94c861605e5b18bb32ed523f50d5b7b5c71d47bc"),
}

k32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
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

def modules(pid):
    TH32CS_SNAPMODULE = 8; TH32CS_SNAPMODULE32 = 16
    k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    k32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    out = []
    if not snap or snap == ctypes.c_void_p(-1).value:
        return out
    me = MODULEENTRY32W(); me.dwSize = ctypes.sizeof(me)
    try:
        ok = k32.Module32FirstW(snap, ctypes.byref(me))
        while ok:
            out.append((me.szModule, int(me.modBaseAddr or 0), me.modBaseSize))
            ok = k32.Module32NextW(snap, ctypes.byref(me))
    finally:
        k32.CloseHandle(snap)
    return out

env = dict(os.environ); env["__COMPAT_LAYER"] = "RunAsInvoker"
f = open(OUT, "wb")
p = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=f, stderr=subprocess.STDOUT, env=env)
print("pid", p.pid, flush=True)
time.sleep(5)

h = k32.OpenProcess(0x1F0FFF, False, p.pid)
print("handle", h, flush=True)
mods = modules(p.pid)
print("modules:", flush=True)
for m in mods:
    print("  %-28s base=%016x size=%08x" % m, flush=True)

hits = []
buf = ctypes.create_string_buffer(0x400000)
rd = ctypes.c_size_t()
addr = 0
regions = 0
while addr < 0x7FFFFFFFFFFF:
    mbi = MBI()
    if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        break
    base = int(mbi.BaseAddress or 0); size = int(mbi.RegionSize or 0)
    if size == 0: break
    regions += 1
    prot = mbi.Protect & 0xFF
    if mbi.State == 0x1000 and not (mbi.Protect & 0x100) and prot not in (0, 1) and size < 0x80000000:
        off = 0
        while off < size:
            n = min(0x400000, size - off)
            if k32.ReadProcessMemory(h, ctypes.c_void_p(base + off), buf, n, ctypes.byref(rd)) and rd.value:
                data = buf.raw[:rd.value]
                for name, pin in PINS.items():
                    pos = 0
                    while True:
                        i = data.find(pin, pos)
                        if i < 0: break
                        hits.append((name, base + off + i, base, size, mbi.Type, mbi.Protect))
                        pos = i + 1
            off += n
    addr = base + size
print("regions scanned", regions, flush=True)
print("hits", len(hits), flush=True)
for hh in hits:
    print("  PIN %s @ %016x region=%016x size=%x type=%x prot=%x" % (hh[0], hh[1], hh[2], hh[3], hh[4], hh[5]), flush=True)
    # nearest module
    best = None
    for name, mb, ms in mods:
        if mb <= hh[1] < mb + ms:
            best = (name, mb, ms); break
    print("     module:", best, flush=True)
k32.CloseHandle(h)
p.terminate(); time.sleep(0.5); f.close()
print("poll", p.poll(), flush=True)
