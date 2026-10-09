import struct

with open(r"H:\xtcz10check\unpacked_xbl\v1.0.1\inner_fv.bin", "rb") as f:
    data = f.read()

# QcomBds PDB @ 0x4297AB
# ?????? "QcomBds" ? PE ??
# ????? MZ ???? PE??????? QcomBds ???

print("=== ???? QcomBds ? PE ?? ===")
pos = 0
found = []
while True:
    mz = data.find(b"MZ", pos)
    if mz < 0: break
    if mz + 0x40 < len(data):
        try:
            pe_off = struct.unpack_from("<I", data, mz+0x3C)[0]
            if pe_off < 0x2000 and mz + pe_off + 24 < len(data):
                if data[mz+pe_off:mz+pe_off+4] == b"PE\x00\x00":
                    machine = struct.unpack_from("<H", data, mz+pe_off+4)[0]
                    if machine == 0xAA64:  # ARM64
                        nsec = struct.unpack_from("<H", data, mz+pe_off+6)[0]
                        optsz = struct.unpack_from("<H", data, mz+pe_off+20)[0]
                        sec_tbl = pe_off + 24 + optsz
                        total = sec_tbl + nsec * 40
                        for s in range(nsec):
                            so = sec_tbl + s * 40
                            rs = struct.unpack_from("<I", data, mz+so+16)[0]
                            rp = struct.unpack_from("<I", data, mz+so+20)[0]
                            total = max(total, rp + rs)
                        # ?????? QcomBds
                        pe_data = data[mz:mz+total]
                        if b"QcomBds" in pe_data or b"BdsBoot" in pe_data or b"BdsMisc" in pe_data:
                            found.append((mz, total, nsec))
                            print(f"  PE @ 0x{mz:X}, size=0x{total:X} ({total}B), sections={nsec}")
                            if b"QcomBds" in pe_data: print("    ? ?? QcomBds")
                            if b"BdsBoot" in pe_data: print("    ? ?? BdsBoot")
                            if b"BdsMisc" in pe_data: print("    ? ?? BdsMisc")
                            if b"BdsConsole" in pe_data: print("    ? ?? BdsConsole")
        except: pass
    pos = mz + 1

if found:
    # ????
    found.sort(key=lambda x: x[1], reverse=True)
    best = found[0]
    print(f"\n??: PE @ 0x{best[0]:X}, size=0x{best[1]:X}")
    pe32 = data[best[0]:best[0]+best[1]]
    out_path = r"H:\xtcz10check\unpacked_xbl\v1.0.1\QcomBds.pe32"
    with open(out_path, "wb") as out:
        out.write(pe32)
    print(f"???: {out_path} ({len(pe32)} bytes)")
else:
    print("????? QcomBds ? PE ??")
