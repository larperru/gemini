import os, sys, time, subprocess, threading
import frida

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
APP = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
USER = os.environ.get("USER", "celnik")
KEY = os.environ.get("KEY", "VT-123456-ABCDEF-GHJKLM")
WAIT = float(os.environ.get("WAIT", "6"))
HOLD = float(os.environ.get("HOLD", "4"))

JS = r"""
const mod = Process.findModuleByName('VanishTrace.exe');
console.log('[frida] module ' + (mod ? mod.base + ' size ' + mod.size : 'NOT FOUND'));
function fmt(a) {
  const m = Process.findModuleByAddress(a);
  if (!m) return a.toString();
  return m.name + '+0x' + a.sub(m.base).toString(16);
}
function bt(ctx) {
  try {
    return Thread.backtrace(ctx, Backtracer.ACCURATE).map(fmt).join(' <- ');
  } catch (e) { return 'bt err ' + e; }
}
const k32 = Process.getModuleByName('kernel32.dll');
const fn = k32.getExportByName('WriteFile');
let n = 0;
Interceptor.attach(fn, {
  onEnter(args) {
    n++;
    const len = args[2].toInt32();
    if (len <= 0 || len > 65536) return;
    let a = '', b = '';
    try { a = Memory.readLatin1String(args[1], len); } catch (e) { }
    try { b = Memory.readUtf16String(args[1], Math.min(len / 2, 32768)); } catch (e) { }
    const s = (a + '\n' + b);
    if (s.indexOf('bad key') >= 0 || s.indexOf('License') >= 0 ||
        s.indexOf('Username') >= 0 || n < 8) {
      console.log('[wf ' + n + '] len=' + len + ' ' + bt(this.context));
      console.log('  A: ' + a.slice(0, 300).replace(/[\x00-\x08\x0b-\x1f]/g, '.'));
      console.log('  W: ' + b.slice(0, 300).replace(/[\x00-\x08\x0b-\x1f]/g, '.'));
    }
  }
});
console.log('[frida] WriteFile hooked');
"""

raw = open(r"C:\Users\celnik__\Desktop\New folder (4)\_work\frida_wf.out", "wb")
env = dict(os.environ)
env["__COMPAT_LAYER"] = "RunAsInvoker"
p = subprocess.Popen([APP], cwd=os.path.dirname(APP), env=env,
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, bufsize=0)
print("[app] pid", p.pid, flush=True)

def reader():
    while True:
        d = p.stdout.read(4096)
        if not d:
            break
        raw.write(d); raw.flush()
threading.Thread(target=reader, daemon=True).start()

time.sleep(WAIT)
session = frida.attach(p.pid)
script = session.create_script(JS)
script.on('message', lambda m, d: print("[js]", m, d or "", flush=True))
script.load()
time.sleep(1.0)

try:
    p.stdin.write((USER + "\r\n").encode()); p.stdin.flush()
    time.sleep(0.5)
    p.stdin.write((KEY + "\r\n").encode()); p.stdin.flush()
    print("[send] credentials", flush=True)
except Exception as e:
    print("[send err]", repr(e), flush=True)

time.sleep(HOLD)
try:
    script.unload()
except Exception:
    pass
try:
    session.detach()
except Exception:
    pass
try:
    p.stdin.close()
except Exception:
    pass
try:
    p.terminate(); p.wait(timeout=5)
except Exception:
    pass
raw.close()
print("[done]", flush=True)
