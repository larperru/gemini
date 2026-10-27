import os, sys, time, ctypes, subprocess
from ctypes import wintypes

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
APP = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
OUT = r"C:\Users\celnik__\Desktop\New folder (4)\_work\runtime_module.bin"
REG = r"C:\Users\celnik__\Desktop\New folder (4)\_work\runtime_regions.txt"
WAIT = float(os.environ.get("WAIT", "7"))
SEND = os.environ.get("SEND", "celnik|VT-123456-ABCDEF-GHJKLM")

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

class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("GlblcntUsage", wintypes.DWORD),
                ("ProccntUsage", wintypes.DWORD), ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", wintypes.DWORD), ("hModule", ctypes.c_void_p),
                ("szModule", wintypes.WCHAR * 256), ("szExePath", wintypes.WCHAR * 260)]

k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
k32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
k32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]

def module_info(pid):
    snap = k32.CreateToolhelp32Snapshot(0x8 | 0x10, pid)
    if not snap or snap == ctypes.c_void_p(-1).value:
        return None, None
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

env = dict(os.environ)
env["__COMPAT_LAYER"] = "RunAsInvoker"
p = subprocess.Popen([APP], cwd=os.path.dirname(APP), env=env,
                     stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
print("[app] pid", p.pid, flush=True)
time.sleep(WAIT)
if SEND:
    user, _, key = SEND.partition("|")
    try:
        p.stdin.write((user + "\r\n").encode()); p.stdin.flush()
        time.sleep(0.5)
        p.stdin.write((key + "\r\n").encode()); p.stdin.flush()
        print("[send] credentials", flush=True)
    except Exception as e:
        print("[send err]", repr(e), flush=True)
    time.sleep(1.5)

base, size = module_info(p.pid)
print("[module] base", hex(base or 0), "size", hex(size or 0), flush=True)
if not base:
    p.terminate(); sys.exit(1)

h = k32.OpenProcess(0x1F0FFF, False, p.pid)
if not h:
    print("[!] OpenProcess failed", ctypes.get_last_error(), flush=True)
    p.terminate(); sys.exit(1)

data = bytearray(size)
got = ctypes.c_size_t()
buf = ctypes.create_string_buffer(0x100000)
off = 0
while off < size:
    n = min(len(buf), size - off)
    if k32.ReadProcessMemory(h, ctypes.c_void_p(base + off), buf, n,
                             ctypes.byref(got)) and got.value:
        data[off:off+got.value] = buf.raw[:got.value]
    off += n
open(OUT, "wb").write(data)
print("[dump]", OUT, len(data), flush=True)

# region map
with open(REG, "w", encoding="utf-8") as f:
    addr = base
    end = base + size
    while addr < end:
        mbi = MBI()
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                                  ctypes.sizeof(mbi)):
            break
        rb = int(mbi.BaseAddress or 0); rs = int(mbi.RegionSize or 0)
        if not rs: break
        f.write("%#x %#x state=%#x prot=%#x type=%#x off=%#x\n" %
                (rb, rs, int(mbi.State), int(mbi.Protect), int(mbi.Type), rb - base))
        addr = rb + rs
k32.CloseHandle(h)
try:
    p.stdin.close()
except Exception:
    pass
try:
    p.terminate(); p.wait(timeout=5)
except Exception:
    pass
print("[done]", flush=True)
