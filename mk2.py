import shutil
src=r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
dst=r"C:\Users\celnik__\Desktop\New folder (4)\_work\vt2.exe"
shutil.copy2(src,dst)
d=bytearray(open(dst,'rb').read())
old=b'level="requireAdministrator"'
new=b'level="asInvoker"           '
i=d.find(old); print("found",hex(i),"len",len(old),len(new))
d[i:i+len(old)]=new
open(dst,'wb').write(d)
print("written",len(d))
