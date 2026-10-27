import pefile, capstone, struct
p = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
pe = pefile.PE(p)
data = open(p,'rb').read()
IB = pe.OPTIONAL_HEADER.ImageBase

def rva2off(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return None

def show(rva, n, label):
    off = rva2off(rva)
    blob = data[off:off+n]
    print(f"\n--- {label} rva={rva:#x} off={off:#x} ({n} bytes) ---")
    print(blob[:64].hex())
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False
    for i in md.disasm(blob, IB+rva):
        print(f"{i.address:016x}  {i.bytes.hex():<24} {i.mnemonic} {i.op_str}")

show(pe.OPTIONAL_HEADER.AddressOfEntryPoint, 200, "ENTRY")
# TLS callbacks
if hasattr(pe,'DIRECTORY_ENTRY_TLS'):
    tls = pe.DIRECTORY_ENTRY_TLS.struct
    print("\nTLS dir:", hex(tls.StartAddressOfRawData), hex(tls.EndAddressOfRawData), hex(tls.AddressOfIndex), hex(tls.AddressOfCallBacks))
    cb_rva = tls.AddressOfCallBacks - IB
    off = rva2off(cb_rva)
    if off:
        for k in range(4):
            v = struct.unpack_from('<Q', data, off+8*k)[0]
            print("callback", k, hex(v))
            if v and 0x140000000 <= v < 0x140000000+0x1300000:
                show(v-IB, 96, f"TLS CALLBACK {k}")

# scan for compression/PE signatures
print("\n=== SIGNATURE SCAN .mDc2 ===")
sec = [s for s in pe.sections if s.Name.startswith(b'.mDc2')][0]
raw = sec.get_data()
pats = {
 b'5D 00 00': None, # lzma props
 b'\x78\x9c': None, b'\x78\xda': None, b'\x78\x01': None,
 b'PK\x03\x04': None, b'MZ': None,
 b'\x1f\x8b\x08': None,
 b'AP32': None, b'aPLib': None,
 b'7z\xbc\xaf\x27\x1c': None, b'Rar!\x1a\x07': None,
}
for pat in pats:
    idx = [m for m in range(len(raw)) if raw.startswith(pat, m)][:10]
    print(repr(pat), "count", len(idx), "offsets", [hex(sec.PointerToRawData+i) for i in idx[:5]])
import math
def ent(b):
    if not b: return 0
    c=[0]*256
    for x in b: c[x]+=1
    return -sum((n/len(b))*math.log2(n/len(b)) for n in c if n)
print("entropy first 0x2000:", round(ent(raw[:0x2000]),3), "last 0x80000:", round(ent(raw[-0x80000:]),3))
print("head:", raw[:32].hex())
print("tail:", raw[-32:].hex())
