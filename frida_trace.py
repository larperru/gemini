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
let hits = 0;
let counts = {};
function report(tag, text, ctx) {
  if (text.indexOf('bad key or username') < 0) return;
  hits++;
  console.log('[HIT ' + tag + '] ' + bt(ctx));
  const i = Math.max(0, text.indexOf('License:') - 40);
  console.log('[TEXT] ' + text.slice(i, i + 220).replace(/[\x00-\x08\x0b-\x1f]/g, '.'));
}
function charInfoText(buf, w, h) {
  const n = Math.min(w * h, 12000);
  let out = '';
  for (let i = 0; i < n; i++) {
    let c = 0;
    try { c = buf.add(i * 4).readU16(); } catch (e) { break; }
    out += (c >= 32 && c < 127) ? String.fromCharCode(c) : ' ';
  }
  return out;
}
const targets = [];
for (const dll of ['kernel32.dll', 'kernelbase.dll']) {
  let m = null;
  try { m = Process.getModuleByName(dll); } catch (e) { continue; }
  for (const name of ['WriteConsoleOutputW', 'WriteConsoleOutputA',
                      'WriteConsoleOutputCharacterW', 'WriteConsoleOutputCharacterA',
                      'WriteConsoleW', 'WriteConsoleA', 'WriteFile']) {
    let fn = null;
    try { fn = m.getExportByName(name); } catch (e) { continue; }
    targets.push([dll + '!' + name, name, fn]);
  }
}
for (const [tag, name, fn] of targets) {
  Interceptor.attach(fn, {
    onEnter(args) {
      counts[tag] = (counts[tag] || 0) + 1;
      if (counts[tag] % 100 === 1) console.log('[call] ' + tag + ' #' + counts[tag]);
      try {
        if (name.indexOf('Character') >= 0) {
          const n = args[2].toInt32();
          let text = '';
          if (name.endsWith('W')) text = Memory.readUtf16String(args[1], n);
          else text = Memory.readLatin1String(args[1], n);
          report(tag, text, this.context);
        } else if (name.indexOf('Output') >= 0) {
          const size = args[2].toInt32() >>> 0;
          const w = size & 0xffff, h = (size >>> 16) & 0xffff;
          report(tag, charInfoText(args[1], w, h), this.context);
        } else if (name === 'WriteFile') {
          const n = args[2].toInt32();
          let text = '';
          try { text = Memory.readUtf16String(args[1], n / 2); } catch (e) { }
          if (text.indexOf('bad') < 0) text = Memory.readLatin1String(args[1], Math.min(n, 20000));
          report(tag, text, this.context);
        } else {
          const n = args[2].toInt32();
          let text = '';
          if (name.endsWith('W')) text = Memory.readUtf16String(args[1], n);
          else text = Memory.readLatin1String(args[1], n);
          report(tag, text, this.context);
        }
      } catch (e) { }
    }
  });
  console.log('[frida] hooked ' + tag);
}
"""

raw = open(r"C:\Users\celnik__\Desktop\New folder (4)\_work\frida_run.out", "wb")
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
