import subprocess, os, time, sys, re

EXE = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
env = dict(os.environ); env['__COMPAT_LAYER'] = 'RunAsInvoker'
OUT = r"C:\Users\celnik__\Desktop\New folder (4)\_work\dump\drive.txt"
steps = sys.argv[1:]
delay = float(os.environ.get('STEP_DELAY', '2.5'))
start_delay = float(os.environ.get('START_DELAY', '4'))

f = open(OUT, 'wb')
p = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=f, stderr=subprocess.STDOUT, env=env)
print("pid", p.pid, flush=True)
time.sleep(start_delay)
for s in steps:
    if p.poll() is not None: break
    try:
        p.stdin.write(s.encode() + b'\r\n'); p.stdin.flush()
    except Exception as e:
        print("write err", e, flush=True); break
    time.sleep(delay)
if p.poll() is None:
    p.terminate(); time.sleep(0.5)
print("poll", p.poll(), flush=True)
f.close()
data = open(OUT,'rb').read().decode('utf-8','replace')
t = re.sub(r'\x1b\][^\x07\x1b]*(\x07|\x1b\\)', '', data)
t = re.sub(r'\x1b\[[0-9;?]*[ -/]*[@-~]', '', t).replace('\x1b','')
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
print("=== TAIL ===")
print(t[-14000:])
