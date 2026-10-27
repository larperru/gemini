import os, sys, time, subprocess, json
import frida

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
APP = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
WAIT = float(os.environ.get("WAIT", "7"))
TRACE_MS = int(os.environ.get("TRACE_MS", "500"))

JS = r"""
let total = 0;
let first = [];
function onRecv(events) {
  let parsed;
  try { parsed = Stalker.parse(events, {annotate: false, stringify: false}); }
  catch (e) { return; }
  total += parsed.length;
  if (first.length < 30) {
    for (const ev of parsed) {
      first.push(String(ev));
      if (first.length >= 30) break;
    }
  }
}
let followed = [];
rpc.exports = {
  start() {
    followed = Process.enumerateThreads();
    for (const t of followed) {
      try { Stalker.follow(t.id, {events: {exec: true}, onReceive: onRecv}); } catch (e) {}
    }
    return followed.map(t => t.id);
  },
  stop() {
    let now = Process.enumerateThreads().map(t => t.id);
    for (const t of followed) { try { Stalker.unfollow(t.id); } catch (e) {} }
    try { Stalker.flush(); } catch (e) {}
    const nf = [];
    for (const a of first.slice(0, 20)) {
      try {
        const p = ptr(a);
        const m = Process.findModuleByAddress(p);
        nf.push(a + ' -> ' + (m ? m.name + '+0x' + p.sub(m.base).toString(16) : 'none'));
      } catch (e) { nf.push(a + ' -> err'); }
    }
    return {total: total, first: nf, followed: followed.map(t => t.id), now: now};
  }
};
console.log('[dbg3] ready threads=' + Process.enumerateThreads().length);
"""

env = dict(os.environ); env["__COMPAT_LAYER"] = "RunAsInvoker"
p = subprocess.Popen([APP], cwd=os.path.dirname(APP), env=env,
                     stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
print("[app] pid", p.pid, flush=True)
time.sleep(WAIT)
session = frida.attach(p.pid)
script = session.create_script(JS)
script.on('message', lambda m, d: print("[js]", m, d or "", flush=True))
script.load()
time.sleep(0.7)
print("[start]", script.exports_sync.start(), flush=True)
try:
    p.stdin.write(b"celnik\r\n"); p.stdin.flush()
    time.sleep(0.3)
    p.stdin.write(b"VT-123456-ABCDEF-GHJKLM\r\n"); p.stdin.flush()
except Exception as e:
    print("[send err]", repr(e), flush=True)
time.sleep(TRACE_MS / 1000.0)
print("[alive]", p.poll() is None, flush=True)
try:
    print("[stop]", json.dumps(script.exports_sync.stop(), indent=2)[:6000], flush=True)
except Exception as e:
    print("[stop err]", repr(e), flush=True)
try: script.unload()
except Exception: pass
try: session.detach()
except Exception: pass
try: p.terminate(); p.wait(timeout=5)
except Exception: pass
print("[done]", flush=True)
