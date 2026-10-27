import os, sys, time, subprocess, threading, json
import frida

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
APP = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
USER = os.environ.get("USER", "celnik")
KEY = os.environ.get("KEY", "VT-123456-ABCDEF-GHJKLM")
WAIT = float(os.environ.get("WAIT", "7"))
TRACE_MS = int(os.environ.get("TRACE_MS", "700"))
OUT = os.environ.get("OUT", r"C:\Users\celnik__\Desktop\New folder (4)\_work\stalker_digit.json")

JS = r"""
const mod = Process.findModuleByName('VanishTrace.exe');
const base = mod.base, end = mod.base.add(mod.size);
const addrs = new Set();
let tracing = false;
let threads = [];

function onRecv(events) {
  let parsed;
  try { parsed = Stalker.parse(events, {annotate: false, stringify: false}); }
  catch (e) { return; }
  for (const ev of parsed) {
    let a = null;
    if (ev && typeof ev === 'object' && ev.length !== undefined) {
      if (ev[0] === 'exec' && ev[1]) a = ev[1];
    } else {
      try { a = ptr(ev); } catch (e) { a = null; }
    }
    if (a && a.compare(base) >= 0 && a.compare(end) < 0) {
      addrs.add(a.sub(base).toString(16));
    }
  }
}

rpc.exports = {
  start() {
    if (tracing) return 0;
    tracing = true;
    threads = Process.enumerateThreads();
    for (const t of threads) {
      try { Stalker.follow(t.id, {events: {exec: true}, onReceive: onRecv}); } catch (e) {}
    }
    return threads.map(t => t.id);
  },
  stop() {
    tracing = false;
    for (const t of threads) {
      try { Stalker.unfollow(t.id); } catch (e) {}
    }
    try { Stalker.flush(); } catch (e) {}
    return Array.from(addrs);
  }
};
console.log('[stalker] ready base=' + base + ' threads=' + Process.enumerateThreads().length);
"""

raw = open(r"C:\Users\celnik__\Desktop\New folder (4)\_work\frida_stalker.out", "wb")
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
time.sleep(0.7)

n = script.exports_sync.start()
print("[trace] started threads=%s" % n, flush=True)
time.sleep(0.2)
try:
    p.stdin.write((USER + "\r\n").encode()); p.stdin.flush()
    time.sleep(0.4)
    p.stdin.write((KEY + "\r\n").encode()); p.stdin.flush()
    print("[send] credentials", flush=True)
except Exception as e:
    print("[send err]", repr(e), flush=True)

time.sleep(TRACE_MS / 1000.0)
print("[app alive]", p.poll() is None, "rc", p.poll(), flush=True)
try:
    addrs = script.exports_sync.stop()
except Exception as e:
    print("[stop err]", repr(e), flush=True)
    addrs = []
print("[trace] addresses=%d" % len(addrs), flush=True)
json.dump(addrs, open(OUT, "w"))
print("[saved]", OUT, flush=True)

try: script.unload()
except Exception: pass
try: session.detach()
except Exception: pass
try: p.stdin.close()
except Exception: pass
try:
    p.terminate(); p.wait(timeout=5)
except Exception: pass
raw.close()
print("[done]", flush=True)
