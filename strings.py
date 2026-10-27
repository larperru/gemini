import pefile, re, os, json, math
p = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
pe = pefile.PE(p)
data = open(p,'rb').read()
OUT = r"C:\Users\celnik__\Desktop\New folder (4)\_work"
os.makedirs(OUT, exist_ok=True)

# map rva -> file offset
def rva2off(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return None

# --- resources, raw dump ---
print("=== RESOURCES ===")
def walk(entries, path=""):
    for e in entries:
        nm = e.name.decode() if e.name is not None else str(e.id)
        if hasattr(e, 'directory'):
            walk(e.directory.entries, path + "/" + nm)
        else:
            d = e.data.struct
            off = rva2off(d.OffsetToData)
            blob = data[off:off+d.Size] if off is not None else b''
            print(f"{path}/{nm:8} rva={d.OffsetToData:#x} size={d.Size:#x} ent={0:.2f} head={blob[:16].hex()}")
            fn = os.path.join(OUT, "res_" + path.strip('/').replace('/','_') + "_" + nm + ".bin")
            open(fn,'wb').write(blob)
walk(pe.DIRECTORY_ENTRY_RESOURCE.entries)

# --- strings ---
def strings(buf, minlen, enc):
    out=[]
    if enc=='a':
        pat = re.compile(rb'[\x20-\x7e]{%d,}' % minlen)
    else:
        pat = re.compile((r'(?:[\x20-\x7e]\x00){%d,}' % minlen).encode())
    for m in pat.finditer(buf):
        s = m.group().decode('utf-16le' if enc=='u' else 'latin1')
        out.append((m.start(), s))
    return out

alls = []
for s in pe.sections:
    name = s.Name.rstrip(b'\0').decode(errors='replace')
    if s.SizeOfRawData == 0: continue
    raw = s.get_data()
    for off, st in strings(raw, 5, 'a'):
        alls.append((name, s.PointerToRawData+off, 'a', st))
    for off, st in strings(raw, 5, 'u'):
        alls.append((name, s.PointerToRawData+off, 'u', st))
print("total strings:", len(alls))
with open(os.path.join(OUT,"strings.txt"),'w',encoding='utf-8',errors='replace') as f:
    for name, off, enc, st in alls:
        f.write(f"{off:08x} {name:8} {enc} {st}\n")

KEY = re.compile(r'(?i)(http|https|://|license|licence|api\.|\.com|\.net|\.ru|\.io|\.xyz|hwid|serial|activation|auth|token|key|expire|discord|telegram|winhttp|bcrypt|evolve|spoofer|vanish|trace|username|password|hwid)')
hits = [x for x in alls if KEY.search(x[3])]
print("keyword hits:", len(hits))
for name, off, enc, st in hits[:400]:
    print(f"  {off:08x} {name:8} {enc} {st[:160]}")
