import shutil, os, sys
src = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
dst = r"C:\Users\celnik__\Desktop\New folder (4)\_work\VanishTrace_analysis.exe"
shutil.copy2(src, dst)
data = bytearray(open(dst,'rb').read())
old = b'level="requireAdministrator"'
new = b'level="asInvoker"           '  # same length
print("old len", len(old), "new len", len(new))
i = data.find(old)
print("manifest level at", hex(i), "count", data.count(old))
assert i != -1 and len(old) == len(new)
data[i:i+len(old)] = new
open(dst,'wb').write(data)
print("patched copy written", dst, len(data))
# verify manifest
import pefile
pe = pefile.PE(dst)
for e in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    if e.id == 24:
        for e2 in e.directory.entries:
            for e3 in e2.directory.entries:
                d = e3.data.struct
                off = pe.get_offset_from_rva(d.OffsetToData)
                print(data[off:off+300].decode('utf-8','replace'))
