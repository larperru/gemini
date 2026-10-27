import subprocess, os, time, sys, re

EXE = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
OUT = r"C:\Users\celnik__\Desktop\New folder (4)\_work\dump\console_run1.txt"
env = dict(os.environ); env['__COMPAT_LAYER'] = 'RunAsInvoker'
f = open(OUT, 'wb')
p = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=f, stderr=subprocess.STDOUT, env=env)
print("pid", p.pid)
for i in range(20):
    time.sleep(0.5)
    if p.poll() is not None: break
print("poll after wait:", p.poll())
if p.poll() is None:
    try:
        p.stdin.write(b'\r\n'); p.stdin.flush()
    except Exception as e: print("stdin err", e)
    time.sleep(2)
    if p.poll() is None:
        p.terminate()
        time.sleep(0.5)
print("final poll:", p.poll())
f.close()
data = open(OUT,'rb').read()
print("output bytes:", len(data))
txt = data.decode('utf-8','replace')
txt = re.sub(r'\x1b\[[0-9;?]*[a-zA-Z]', '', txt)
txt = re.sub(r'\x1b\][^\x07]*\x07', '', txt)
print("----- tail -----")
print(txt[-4000:])
