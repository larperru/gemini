import os, sys, time, subprocess, threading
import frida

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
APP = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
USER = os.environ.get("USER", "celnik")
KEY = os.environ.get("KEY", "VT-123456-ABCDEF-GHJKLM")
WAIT = float(os.environ.get("WAIT", "6"))
HOLD = float(os.environ.get("HOLD", "4"))

JS = r"""
function fmt(a) {
  const m = Process.findModuleByAddress(a);
  if (!m) return a.toString();
  return m.name + '+0x' + a.sub(m.base).toString(16);
}
function bt(ctx) {
  try { return Thread.backtrace(ctx, Backtracer.ACCURATE).map(fmt).join(' <- '); }
  catch (e) { return 'bt err ' + e; }
}
const k32 = Process.getModuleByName('kernel32.dll');
const kb = Process.getModuleByName('kernelbase.dll');
const getStd = new NativeFunction(k32.getExportByName('GetStdHandle'), 'pointer', ['int']);
const stdinH = getStd(-10);
console.log('[stdin] handle ' + stdinH);
for (const [tag, fn] of [
  ['ReadFile.k32', k32.getExportByName('ReadFile')],
  ['ReadFile.kb', kb.getExportByName('ReadFile')],
]) {
  Interceptor.attach(fn, {
    onEnter(args) {
      this.h = args[0]; this.buf = args[1]; this.n = args[2].toInt32();
      this.rd = args[3]; this.tid = Process.getCurrentThreadId();
    },
    onLeave(ret) {
      let got = 0;
      try { got = this.rd.readU32(); } catch (e) {}
      const isIn = this.h.equals(stdinH);
      if (isIn || got > 0) {
        let txt = '';
        try { txt = Memory.readUtf8String(this.buf, Math.min(got, 200)); } catch (e) {}
        console.log('[' + tag + '] tid=' + this.tid + ' h=' + this.h + ' n=' + this.n +
                    ' got=' + got + ' ret=' + ret + ' text=' + JSON.stringify(txt));
        if (isIn) console.log('  BT ' + bt(this.context));
      }
    }
  });
  console.log('[hooked] ' + tag);
}
for (const [tag, fn] of [
  ['ReadConsoleInputW', k32.getExportByName('ReadConsoleInputW')],
]) {
  Interceptor.attach(fn, {
    onEnter(args) { this.tid = Process.getCurrentThreadId(); },
    onLeave(ret) {
      console.log('[' + tag + '] tid=' + this.tid + ' ret=' + ret + ' BT ' + bt(this.context));
    }
  });
  console.log('[hooked] ' + tag);
}
"""

raw = open(r"C:\Users\celnik__\Desktop\New folder (4)\_work\frida_in.out", "wb")
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
try: script.unload()
except Exception: pass
try: session.detach()
except Exception: pass
try: p.stdin.close()
except Exception: pass
try: p.terminate(); p.wait(timeout=5)
except Exception: pass
raw.close()
print("[done]", flush=True)
