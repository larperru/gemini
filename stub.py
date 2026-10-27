import pefile, capstone
p = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
pe = pefile.PE(p)
data = open(p,'rb').read()
IB = pe.OPTIONAL_HEADER.ImageBase
secs = {s.Name.rstrip(b'\0').decode(): s for s in pe.sections}
def rva2off(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.PointerToRawData + (rva - s.VirtualAddress)
def show(rva, n, label, base=True):
    off = rva2off(rva); blob = data[off:off+n]
    print(f"\n--- {label} rva={rva:#x} off={off:#x} ---")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for i in md.disasm(blob, IB+rva if base else rva):
        print(f"{i.address:016x}  {i.bytes.hex():<20} {i.mnemonic} {i.op_str}")
show(0x11fe85f, 240, "STUB TARGET")
# mDc1 dump text
s = secs['.mDc1']; raw = s.get_data()
print("\n=== .mDc1 hexdump (first 0x400) ===")
for i in range(0, min(0x400,len(raw)), 16):
    chunk = raw[i:i+16]
    print(f"{s.PointerToRawData+i:08x}  {chunk.hex(' '):<48}  {''.join(chr(c) if 32<=c<127 else '.' for c in chunk)}")
print("\n=== .mDc1 ascii strings ===")
import re
for m in re.finditer(rb'[\x20-\x7e]{4,}', raw):
    print(hex(s.PointerToRawData+m.start()), m.group().decode())
