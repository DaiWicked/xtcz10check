import struct

def hexdump_range(data, start, length):
    for i in range(start, min(start+length, len(data)), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        print(f'{i:08x}: {hex_part:<48} {ascii_part}')

def find_descriptors(data):
    """在数据中搜索描述符"""
    print("\n=== 搜索描述符 ===")
    # 描述符通常从偏移 256 之后开始
    # 尝试从偏移 256 开始解析
    pos = 256
    while pos + 16 <= len(data):
        tag = struct.unpack_from('>Q', data, pos)[0]
        num_bytes = struct.unpack_from('>Q', data, pos+8)[0]

        # 合理的描述符 tag 是 0-6
        if 0 <= tag <= 6 and num_bytes > 0 and num_bytes < 10000:
            tag_names = {0: "HASHTREE", 1: "HASH", 2: "CHAIN_PARTITION",
                        3: "ATX_UNLOCK", 4: "PROPERTY", 5: "CMDLINE", 6: "CHAIN_EXT"}
            name = tag_names.get(tag, f"UNKNOWN({tag})")

            info = f"偏移 {pos}: {name}, size={num_bytes}"

            # HASH 描述符：分区名在偏移 56
            if tag == 1 and num_bytes >= 56:
                pname = data[pos+56:pos+88].split(b'\x00')[0].decode('ascii', errors='replace')
                info += f", partition={pname}"

            # CHAIN_PARTITION：分区名在偏移 24
            if tag == 2 and num_bytes >= 24:
                pname = data[pos+24:pos+56].split(b'\x00')[0].decode('ascii', errors='replace')
                info += f", partition={pname}"

            print(info)
            pos += 16 + num_bytes
            if pos % 8 != 0:
                pos += 8 - (pos % 8)
        else:
            pos += 8

# 分析作者 vbmeta.img
path = r"H:\xtcz10check\AllToolBox1.4.6\bin\EDL\rooting\vbmeta.img"
with open(path, 'rb') as f:
    data = f.read()

print(f"文件: {path}")
print(f"大小: {len(data)}")

print("\n=== 偏移 256-512 ===")
hexdump_range(data, 256, 256)

print("\n=== 偏移 512-1024 ===")
hexdump_range(data, 512, 512)

find_descriptors(data)

# 同样分析 vbmeta_system.img
path2 = r"H:\xtcz10check\AllToolBox1.4.6\bin\EDL\rooting\vbmeta_system.img"
with open(path2, 'rb') as f:
    data2 = f.read()

print(f"\n\n文件: {path2}")
print(f"大小: {len(data2)}")
print("\n=== 偏移 256-512 ===")
hexdump_range(data2, 256, 256)
find_descriptors(data2)
