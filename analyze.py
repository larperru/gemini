import pefile, math, sys, os, hashlib

p = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
pe = pefile.PE(p, fast_load=False)
data = open(p, 'rb').read()

def ent(b):
    if not b: return 0
    c = [0]*256
    for x in b: c[x]+=1
    e=0
    for n in c:
        if n:
            pr=n/len(b); e-=pr*math.log2(pr)
    return e

print("=== FILE ===")
print("size", len(data), "sha256", hashlib.sha256(data).hexdigest())
print("machine", hex(pe.FILE_HEADER.Machine), "subsys", pe.OPTIONAL_HEADER.Subsystem,
      "entry", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), "imagebase", hex(pe.OPTIONAL_HEADER.ImageBase))
print("checksum", hex(pe.OPTIONAL_HEADER.CheckSum), "dllchars", hex(pe.OPTIONAL_HEADER.DllCharacteristics))
print("linker", pe.OPTIONAL_HEADER.MajorLinkerVersion, pe.OPTIONAL_HEADER.MinorLinkerVersion)
print("timestamp", pe.FILE_HEADER.TimeDateStamp)
print("\n=== SECTIONS ===")
for s in pe.sections:
    raw = s.get_data()
    print(f"{s.Name.decode(errors='replace').rstrip(chr(0)):10} VA={s.VirtualAddress:#010x} VS={s.Misc_VirtualSize:#010x} "
          f"RAW={s.SizeOfRawData:#010x} PTR={s.PointerToRawData:#010x} flags={s.Characteristics:#010x} ent={ent(raw):.2f}")
print("\n=== DIRECTORIES ===")
for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
    if d.VirtualAddress or d.Size:
        name = d.name.replace('IMAGE_DIRECTORY_ENTRY_','')
        print(f"{name:24} RVA={d.VirtualAddress:#010x} SIZE={d.Size:#010x}")

print("\n=== IMPORTS ===")
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for e in pe.DIRECTORY_ENTRY_IMPORT:
        print("--", e.dll.decode(errors='replace'))
        for imp in e.imports[:400]:
            print("   ", (imp.name or b'').decode(errors='replace'), "ord", imp.ordinal, "iat", hex(imp.address))
else:
    print("(none parsed)")

print("\n=== EXPORTS ===")
if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    print("name", pe.DIRECTORY_ENTRY_EXPORT.name)
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        print("  ", e.ordinal, e.name, hex(e.address))
else:
    print("(none)")

print("\n=== RESOURCES ===")
def walk(res, lvl=0):
    for e in res:
        if hasattr(e, 'directory'):
            print("  "*lvl, e.name, e.id, "dir")
            walk(e.directory, lvl+1)
        else:
            d = e.data.struct
            print("  "*lvl, "leaf id", e.id, "rva", hex(d.OffsetToData), "size", d.Size)
if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
    walk(pe.DIRECTORY_ENTRY_RESOURCE.entries)

print("\n=== OVERLAY ===")
ov = pe.get_overlay()
print("overlay size", len(ov) if ov else 0)
if ov:
    print("first 64:", ov[:64].hex())

print("\n=== TLS / LOADCFG / OTHER ===")
for attr in ('DIRECTORY_ENTRY_TLS','DIRECTORY_ENTRY_LOAD_CONFIG','DIRECTORY_ENTRY_BASERELOC','DIRECTORY_ENTRY_DEBUG','DIRECTORY_ENTRY_BOUND_IMPORT'):
    print(attr, "yes" if hasattr(pe, attr) else "no")
    if hasattr(pe, attr):
        try:
            print("   ", pe.__getattribute__(attr))
        except Exception as ex:
            print("   err", ex)
    break
