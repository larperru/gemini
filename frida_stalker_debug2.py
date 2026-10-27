import os, sys, time, subprocess, threading, json
import frida

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
APP = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
WAIT = float(os.environ.get("WAIT", "7"))
TRACE_MS = int(os.environ.get("TRACE_MS", "500"))

JS = r"""
const mod = Process.findModuleByName('VanishTrace.exe');
const base = mod.base, end = mod.base.add(mod.size);
let total = 0, ptrs = 0, arrs = 0, inMod = 0, samples = [], modSamples = [], errs = [];
function onRecv(events) {
  let parsed;
  try { parsed = Stalker.parse(events, {annotate: false, stringify: false}); }
  catch (e) { errs.push('parse:' + e); return; }
  total += parsed.length;
  for (const ev of parsed) {
    let a = null;
    if (ev && typeof ev === 'object' && ev.length !== undefined) {
      arrs++;
      if (ev[0] === 'exec' && ev[1]) a = ev[1];
    } else {
      ptrs++;
      try { a = ptr(ev); } catch (e) { a = null; }
    }
    if (samples.length < 8) samples.push(String(ev) + ' type=' + (typeof ev));
    if (a) {
      if (a.compare(base) >= 0 && a.compare(end) < 0) {
        inMod++;
        if (modSamples.length < 20) modSamples.push(a.sub(base).toString(16));
      }
    }
  }
}
const threads = Process.enumerateThreads();
rpc.exports = {
  start() {
    for (const t of threads) {
      try { Stalker.follow(t.id, {events: {exec: true}, onReceive: onRecv}); }
      catch (e) { errs.push('follow ' + t.id + ': ' + e); }
    }
    return threads.map(t => t.id);
  },
  stop() {
    for (const t of threads) { try { Stalker.unfollow(t.id); } catch (e) {} }
    try { Stalker.flush(); } catch (e) {}
    return {total: total, ptrs: ptrs, arrs: arrs, inMod: inMod,
            samples: samples, modSamples: modSamples, errs: errs,
            base: base.toString(), end: end.toString()};
  }
};
console.log('[dbg2] ready threads=' + threads.length + ' base=' + base + ' end=' + end);
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
print("[stop]", json.dumps(script.exports_sync.stop(), indent=2)[:6000], flush=True)
try: script.unload()
except Exception: pass
try: session.detach()
except Exception: pass
try: p.terminate(); p.wait(timeout=5)
except Exception: pass
print("[done]", flush=True)
