import re, sys
p = r"C:\Users\celnik__\Desktop\New folder (4)\_work\dump\console_run1.txt"
data = open(p,'rb').read().decode('utf-8','replace')
# strip CSI + OSC
t = re.sub(r'\x1b\][^\x07\x1b]*(\x07|\x1b\\)', '', data)
t = re.sub(r'\x1b\[[0-9;?]*[ -/]*[@-~]', '', t)
t = t.replace('\x1b','')
# split frames by form feed / clear markers lost; use "GOODBYE"/menu text heuristics
open(r"C:\Users\celnik__\Desktop\New folder (4)\_work\dump\console_clean.txt",'w',encoding='utf-8').write(t)
print("clean len", len(t))
print("keyword counts:")
for k in ['license','License','LICENSE','username','Username','key','Key','admin','Admin','error','Error','invalid','Invalid','VanishTrace','LOGIN','Login','SPOOFERS','Settings','SUCCESS','FAILED','trial','expire']:
    print(f"  {k}: {t.count(k)}")
# show last 3000 chars
print("---- tail ----")
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
print(t[-3000:])
