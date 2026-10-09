import struct

with open(r"H:\xtcz10check\unpacked_xbl\v1.0.1\inner_fv.bin", "rb") as f:
    data = f.read()

pos = data.find(b"QcomBds.dll")
print(f"QcomBds.dll @ 0x{pos:X}")

# ??????? FFS ???????
search_start = max(0, pos - 0x10000)
candidates = []
for i in range(pos, search_start, -1):
    if i + 24 < len(data):
        size = data[i+21] | (data[i+22] << 8) | (data[i+23-1] << 16)  # ???size ? 3 ???i+21, i+22, i+23
        # ???FFS ???? GUID[16] + hdr_chk[1] + file_chk[1] + type[1] + attr[1] + size[3] + state[1]
        # ?? size ? i+20, i+21, i+22 (?? i+21, i+22, i+23)
        pass

# ???????? FFS ???
# 0-15: File GUID
# 16: Header Checksum
# 17: File Checksum
# 18: Type
# 19: Attributes
# 20-22: Size (3 bytes, little-endian)
# 23: State
for i in range(pos, search_start, -1):
    if i + 24 < len(data):
        size = data[i+20] | (data[i+21] << 8) | (data[i+22] << 16)
        if 0x1000 < size < 0x80000:
            ftype = data[i+18]
            state = data[i+23]
            if ftype in [0x07, 0x08, 0x10] and state in [0x00, 0xF8, 0xFE, 0xFF]:
                if i > 0 and data[i-1] in [0x00, 0xFF]:
                    if i + size > pos:
                        candidates.append((i, size, ftype, state))
                        print(f"FFS @ 0x{i:X}, size=0x{size:X}, type=0x{ftype:02X}, state=0x{state:02X}")

if candidates:
    candidates.sort(key=lambda x: x[1], reverse=True)
    best = candidates[0]
    print(f"\nBest: FFS @ 0x{best[0]:X}, size=0x{best[1]:X}")
    module_data = data[best[0]:best[0]+best[1]]
    mz_pos = module_data.find(b"MZ")
    if mz_pos >= 0:
        print(f"MZ @ 0x{mz_pos:X}")
        pe32 = module_data[mz_pos:]
        if len(pe32) > 0x3C:
            pe_off = struct.unpack_from("<I", pe32, 0x3C)[0]
            if pe_off + 24 < len(pe32) and pe32[pe_off:pe_off+4] == b"PE\x00\x00":
                nsec = struct.unpack_from("<H", pe32, pe_off+6)[0]
                optsz = struct.unpack_from("<H", pe32, pe_off+20)[0]
                sec_tbl = pe_off + 24 + optsz
                total = sec_tbl + nsec * 40
                for s in range(nsec):
                    so = sec_tbl + s * 40
                    rs = struct.unpack_from("<I", pe32, so+16)[0]
                    rp = struct.unpack_from("<I", pe32, so+20)[0]
                    total = max(total, rp + rs)
                print(f"PE size: 0x{total:X} = {total} bytes, sections={nsec}")
                pe32 = pe32[:total]
        with open(r"H:\xtcz10check\unpacked_xbl\v1.0.1\QcomBds.pe32", "wb") as out:
            out.write(pe32)
        print(f"Saved {len(pe32)} bytes")
