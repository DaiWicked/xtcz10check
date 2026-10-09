import struct

with open(r"H:\xtcz10check\unpacked_xbl\v1.0.1\inner_fv.bin", "rb") as f:
    data = f.read()

pos = data.find(b"QcomBds.dll")
print(f"QcomBds.dll @ 0x{pos:X}")

# ?????? pos ??? FFS ??size ??? 0x3000-0x30000 ??
search_start = max(0, pos - 0x10000)
candidates = []
for i in range(pos, search_start, -1):
    if i + 24 < len(data):
        size = data[i+20] | (data[i+21] << 8) | (data[i+22] << 16)
        if 0x3000 <= size <= 0x30000:  # ??????
            ftype = data[i+18]
            state = data[i+23]
            if ftype in [0x07, 0x08, 0x10] and state in [0x00, 0xF8, 0xFE, 0xFF]:
                if i > 0 and data[i-1] in [0x00, 0xFF]:
                    if i + size > pos and i + size < pos + 0x30000:  # ????????? pos ????
                        candidates.append((i, size, ftype, state))
                        print(f"FFS @ 0x{i:X}, size=0x{size:X} ({size}B), type=0x{ftype:02X}, end=0x{i+size:X}")

# ??????????
if candidates:
    candidates.sort(key=lambda x: x[1])
    best = candidates[0]
    print(f"\n?????: FFS @ 0x{best[0]:X}, size=0x{best[1]:X}")
    module_data = data[best[0]:best[0]+best[1]]
    
    # ?? MZ
    mz_positions = []
    idx = 0
    while True:
        mz = module_data.find(b"MZ", idx)
        if mz < 0: break
        # ?? PE
        if mz + 0x40 < len(module_data):
            pe_off = struct.unpack_from("<I", module_data, mz+0x3C)[0]
            if pe_off < 0x1000 and mz + pe_off + 4 < len(module_data):
                if module_data[mz+pe_off:mz+pe_off+4] == b"PE\x00\x00":
                    mz_positions.append(mz)
        idx = mz + 1
    
    print(f"?? {len(mz_positions)} ??? PE ?")
    for mz in mz_positions:
        pe_off = struct.unpack_from("<I", module_data, mz+0x3C)[0]
        machine = struct.unpack_from("<H", module_data, mz+pe_off+4)[0]
        nsec = struct.unpack_from("<H", module_data, mz+pe_off+6)[0]
        print(f"  MZ @ 0x{mz:X}, machine=0x{machine:04X}, sections={nsec}")
    
    if mz_positions:
        mz_pos = mz_positions[0]
        pe32 = module_data[mz_pos:]
        pe_off = struct.unpack_from("<I", pe32, 0x3C)[0]
        nsec = struct.unpack_from("<H", pe32, pe_off+6)[0]
        optsz = struct.unpack_from("<H", pe32, pe_off+20)[0]
        sec_tbl = pe_off + 24 + optsz
        total = sec_tbl + nsec * 40
        for s in range(nsec):
            so = sec_tbl + s * 40
            rs = struct.unpack_from("<I", pe32, so+16)[0]
            rp = struct.unpack_from("<I", pe32, so+20)[0]
            total = max(total, rp + rs)
        print(f"\nPE size: 0x{total:X} = {total} bytes")
        pe32 = pe32[:total]
        
        out_path = r"H:\xtcz10check\unpacked_xbl\v1.0.1\QcomBds.pe32"
        with open(out_path, "wb") as out:
            out.write(pe32)
        print(f"???: {out_path} ({len(pe32)} bytes)")
        
        # ????? QcomBds ???
        if b"QcomBds" in pe32:
            print("? PE32 ??? QcomBds ???")
        else:
            print("? PE32 ???? QcomBds ???")
        if b"BdsBoot" in pe32 or b"BdsMisc" in pe32 or b"BdsConsole" in pe32:
            print("? PE32 ??? BDS ?????")
        else:
            print("? PE32 ???? BDS ?????")
