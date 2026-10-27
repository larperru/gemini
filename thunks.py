import pefile, capstone, struct
p = r"C:\Users\celnik__\Desktop\New folder (4)\VanishTrace.exe"
pe = pefile.PE(p)
data = open(p,'rb').read()
IB = pe.OPTIONAL_HEADER.ImageBase
def rva2off(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.PointerToRawData + (rva - s.VirtualAddress)
def show(rva, n, label):
    off = rva2off(rva); blob = data[off:off+n]
    print(f"\n--- {label} rva={rva:#x} off={off:#x} ---")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for i in md.disasm(blob, IB+rva):
        print(f"{i.address:016x}  {i.bytes.hex():<22} {i.mnemonic} {i.op_str}")
        if i.address > IB+rva+0x80: break

# import descriptors
imp_rva = 0x10b9078
off = rva2off(imp_rva)
print("=== IMPORT DESCRIPTORS raw @", hex(off), "===")
for i in range(0, 0x2a8, 20):
    oft, ts, fc, name, ft = struct.unpack_from('<IIIII', data, off+i)
    if not any((oft,ts,fc,name,ft)): break
    nm = data[rva2off(name):data.index(b'\0', rva2off(name))].decode(errors='replace')
    print(f"OFT={oft:#x} Time={ts:#x} Fwd={fc:#x} Name={name:#x} '{nm}' FT={ft:#x}")

# iat thunks
print("\n=== IAT / THUNK TABLE @0x8c0000 ===")
off = rva2off(0x8c0000)
for i in range(0, 0x260, 16):
    a, b = struct.unpack_from('<QQ', data, off+i)
    print(f"[{i//16:02}] va={a:#x} rva={a-IB:#x} b={b:#x}")

# first few thunks disasm
for rva in [0x10f5258, 0x10a2d94, 0x10b95b2]:
    show(rva, 64, f"THUNK {rva:#x}")

# entry thunk chain
show(0x11fe85f+2, 8, "ENTRY+2 jmp target calc")
