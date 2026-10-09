import struct

with open(r"H:\xtcz10check\unpacked_abl\v1.0.1\abl_pe32_clean.bin", "rb") as f:
    data = f.read(0x2000)

pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
print(f"PE offset: 0x{pe_offset:X}")

opt_offset = pe_offset + 0x18
magic = struct.unpack_from("<H", data, opt_offset)[0]
print(f"Magic: 0x{magic:04X} (0x20B=PE32+)")

image_base = struct.unpack_from("<Q", data, opt_offset + 0x18)[0]
print(f"ImageBase: 0x{image_base:X}")

size_of_image = struct.unpack_from("<I", data, opt_offset + 0x38)[0]
print(f"SizeOfImage: 0x{size_of_image:X}")

num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
print(f"Sections: {num_sections}")
sec_offset = opt_offset + 0xF0
for i in range(num_sections):
    name = data[sec_offset + i*40:sec_offset + i*40 + 8].rstrip(b'\x00').decode('ascii', errors='replace')
    va = struct.unpack_from("<I", data, sec_offset + i*40 + 12)[0]
    raw_size = struct.unpack_from("<I", data, sec_offset + i*40 + 16)[0]
    raw_ptr = struct.unpack_from("<I", data, sec_offset + i*40 + 20)[0]
    print(f"  {name}: VA=0x{va:X}, RawSize=0x{raw_size:X}, RawPtr=0x{raw_ptr:X}")
