import frida, sys, time, os, json, threading

EXE = r"C:\Users\celnik__\Desktop\New folder (4)\_work\vt2.exe"
OUT = r"C:\Users\celnik__\Desktop\New folder (4)\_work\dump"
os.makedirs(OUT, exist_ok=True)
JS = open(r"C:\Users\celnik__\Desktop\New folder (4)\_work\hook.js", encoding="utf-8").read()
logf = open(os.path.join(OUT, "events.log"), "w", encoding="utf-8", buffering=1)

done = threading.Event()

def on_message(msg, data):
    if msg['type'] == 'send':
        p = msg['payload']
        if isinstance(p, dict) and p.get('t') == 'dumpdata':
            fn = os.path.join(OUT, p['path'])
            open(fn, 'wb').write(data)
            print("[dump written]", fn, len(data))
            return
        line = json.dumps(p, ensure_ascii=False)
        logf.write(line + "\n")
        if isinstance(p, dict) and p.get('t') not in ('GetProcAddress',):
            print(line[:500])
        if isinstance(p, dict) and p.get('t') == 'done_dump':
            done.set()
    else:
        print("[frida]", msg)
        logf.write("[frida] " + json.dumps(msg) + "\n")

dev = frida.get_local_device()
print("spawn", EXE)
pid = dev.spawn([EXE])
print("pid", pid)
session = dev.attach(pid)
script = session.create_script(JS)
script.on('message', on_message)
script.load()
dev.resume(pid)
print("resumed")

start = time.time()
while time.time() - start < 25 and not done.is_set():
    time.sleep(0.5)

try:
    dev.get_process(pid)
    alive = True
except Exception:
    alive = False
print("alive after", round(time.time()-start,1), "sec:", alive)
if alive:
    try: dev.kill(pid)
    except Exception as e: print("kill err", e)
logf.close()
print("done")
