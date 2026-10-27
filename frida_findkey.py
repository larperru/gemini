import os, sys, time, subprocess
import frida

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
APP = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
USER = os.environ.get("USER", "celnik")
KEY = os.environ.get("KEY", "VT-123456-ABCDEF-GHJKLM")
WAIT = float(os.environ.get("WAIT", "7"))

JS = r"""
const user = %s;
const key = %s;
function hexpat(s, wide) {
  let out = [];
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    out.push(('0' + (c & 0xff).toString(16)).slice(-2));
    if (wide) out.push('00');
  }
  return out.join(' ');
}
function scan(tag, pattern) {
  const hits = [];
  const ranges = Process.enumerateRanges('r--');
  for (const r of ranges) {
    let m = [];
    try { m = Memory.scanSync(r.base, r.size, pattern); } catch (e) { continue; }
    for (const x of m) {
      let mod = Process.findModuleByAddress(x.address);
      hits.push({tag: tag, addr: x.address.toString(), size: x.size,
                 module: mod ? mod.name : 'private',
                 off: mod ? x.address.sub(mod.base).toString(16) : null,
                 range: r.base.toString() + '+' + r.size.toString(16) + ' ' + r.protection});
      if (hits.length > 50) return hits;
    }
  }
  return hits;
}
rpc.exports = { scanall() {
  return {
    ascii: scan('ascii', hexpat(key, false)),
    wide: scan('wide', hexpat(key, true)),
    user_ascii: scan('user_ascii', hexpat(user, false)),
    user_wide: scan('user_wide', hexpat(user, true))
  };
}};
console.log('[findkey] ready');
"""

env = dict(os.environ); env["__COMPAT_LAYER"] = "RunAsInvoker"
p = subprocess.Popen([APP], cwd=os.path.dirname(APP), env=env,
                     stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
print("[app] pid", p.pid, flush=True)
time.sleep(WAIT)
try:
    p.stdin.write((USER + "\r\n").encode()); p.stdin.flush()
    time.sleep(0.4)
    p.stdin.write((KEY + "\r\n").encode()); p.stdin.flush()
    print("[send] credentials", flush=True)
except Exception as e:
    print("[send err]", repr(e), flush=True)
time.sleep(1.5)

session = frida.attach(p.pid)
script = session.create_script(JS % (repr(USER), repr(KEY)))
script.on('message', lambda m, d: print("[js]", m, d or "", flush=True))
script.load()
time.sleep(0.5)
import json
print(json.dumps(script.exports_sync.scanall(), indent=2), flush=True)
try: script.unload()
except Exception: pass
try: session.detach()
except Exception: pass
try: p.terminate(); p.wait(timeout=5)
except Exception: pass
print("[done]", flush=True)
