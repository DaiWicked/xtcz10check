import struct

def find_avb0(data):
    """在数据中查找 AVB0 魔数"""
    pos = data.find(b'AVB0')
    return pos

def parse_avb_header(data, offset=0):
    """解析 AVB 头部，offset 是 AVB0 的位置"""
    base = offset

    magic = data[base:base+4]
    if magic != b'AVB0':
        return None

    # 正确的 AVB 头部偏移
    auth_size = struct.unpack_from('<Q', data, base+12)[0]
    aux_size = struct.unpack_from('<Q', data, base+20)[0]
    algo = struct.unpack_from('<I', data, base+28)[0]
    hash_offset = struct.unpack_from('<Q', data, base+32)[0]
    hash_size = struct.unpack_from('<Q', data, base+40)[0]
    sig_offset = struct.unpack_from('<Q', data, base+48)[0]
    sig_size = struct.unpack_from('<Q', data, base+56)[0]
    pubkey_offset = struct.unpack_from('<Q', data, base+64)[0]
    pubkey_size = struct.unpack_from('<Q', data, base+72)[0]
    pubkey_meta_offset = struct.unpack_from('<Q', data, base+80)[0]
    pubkey_meta_size = struct.unpack_from('<Q', data, base+88)[0]
    desc_offset = struct.unpack_from('<Q', data, base+96)[0]
    desc_size = struct.unpack_from('<Q', data, base+104)[0]
    rollback = struct.unpack_from('<Q', data, base+112)[0]
    flags = struct.unpack_from('<I', data, base+120)[0]

    algo_names = {
        0: "NONE", 1: "SHA256_RSA2048", 2: "SHA256_RSA4096", 3: "SHA256_RSA8192",
        4: "SHA512_RSA2048", 5: "SHA512_RSA4096", 6: "SHA512_RSA8192",
        7: "SHA256_ECDSA_P256", 8: "SHA512_ECDSA_P521",
    }

    result = {
        'offset': base,
        'algo': algo,
        'algo_name': algo_names.get(algo, f'UNKNOWN({algo})'),
        'flags': flags,
        'rollback': rollback,
        'auth_size': auth_size,
        'aux_size': aux_size,
        'sig_offset': sig_offset,
        'sig_size': sig_size,
        'pubkey_offset': pubkey_offset,
        'pubkey_size': pubkey_size,
        'desc_offset': desc_offset,
        'desc_size': desc_size,
        'hash_offset': hash_offset,
        'hash_size': hash_size,
    }

    # 解析描述符
    descriptors = []
    if desc_size > 0 and base + desc_offset + desc_size <= len(data):
        pos = base + desc_offset
        end = base + desc_offset + desc_size
        while pos + 16 <= end:
            desc_tag = struct.unpack_from('<Q', data, pos)[0]
            desc_num_bytes = struct.unpack_from('<Q', data, pos+8)[0]
            tag_names = {
                0: "HASHTREE", 1: "HASH", 2: "CHAIN_PARTITION",
                3: "ATX_LIB_UNLOCK", 4: "PROPERTY", 5: "KERNEL_CMDLINE",
                6: "CHAIN_PARTITION_EXT",
            }
            tag_name = tag_names.get(desc_tag, f'UNKNOWN({desc_tag})')

            info = {'tag': tag_name, 'size': desc_num_bytes}

            # HASH 描述符：分区名在偏移 56 处
            if desc_tag == 1 and desc_num_bytes >= 56:
                pname = data[pos+56:pos+88].split(b'\x00')[0].decode('ascii', errors='replace')
                info['partition'] = pname

            # CHAIN_PARTITION：分区名在偏移 24 处
            if desc_tag == 2 and desc_num_bytes >= 24:
                pname = data[pos+24:pos+56].split(b'\x00')[0].decode('ascii', errors='replace')
                info['partition'] = pname

            descriptors.append(info)
            pos += 16 + desc_num_bytes
            if pos % 8 != 0:
                pos += 8 - (pos % 8)

    result['descriptors'] = descriptors
    return result

def analyze_file(path):
    print(f"\n{'='*60}")
    print(f"文件: {path}")
    with open(path, 'rb') as f:
        data = f.read()
    print(f"大小: {len(data)} 字节")

    # 查找 AVB0
    avb_pos = find_avb0(data)
    if avb_pos == -1:
        print("未找到 AVB0 魔数！")
        print(f"前 32 字节: {data[:32].hex()}")
        # 检查是否有高通签名头
        if data[:4] == b'\x9a\xb4\x01=':
            print("检测到高通签名头 (9a b4 01 3d)")
        return

    print(f"AVB0 位置: 偏移 {avb_pos}")
    if avb_pos > 0:
        print(f"前 {avb_pos} 字节是签名头/其他数据")
        print(f"签名头前 32 字节: {data[:32].hex()}")

    hdr = parse_avb_header(data, avb_pos)
    if hdr:
        print(f"\n算法: {hdr['algo_name']}")
        print(f"Flags: {hdr['flags']} (0=正常, 1=禁用验证, 2=禁用验证+错误)")
        print(f"Rollback: {hdr['rollback']}")
        print(f"签名: 偏移={hdr['sig_offset']}, 大小={hdr['sig_size']}")
        print(f"公钥: 偏移={hdr['pubkey_offset']}, 大小={hdr['pubkey_size']}")
        print(f"描述符: 偏移={hdr['desc_offset']}, 大小={hdr['desc_size']}")

        print(f"\n描述符列表 ({len(hdr['descriptors'])} 个):")
        for d in hdr['descriptors']:
            pname = d.get('partition', '')
            print(f"  - {d['tag']}: 大小={d['size']}, 分区={pname}")

        # flags 解读
        if hdr['flags'] == 0:
            print("\n★ Flags=0: 正常验证模式")
        elif hdr['flags'] == 1:
            print("\n★ Flags=1: 禁用哈希验证（允许修改分区）")
        elif hdr['flags'] == 2:
            print("\n★ Flags=2: 禁用验证 + 错误")
        elif hdr['flags'] == 3:
            print("\n★ Flags=3: 完全禁用验证")

# 分析所有文件
files = [
    r"H:\xtcz10check\AllToolBox1.4.6\bin\EDL\rooting\vbmeta.img",
    r"H:\xtcz10check\AllToolBox1.4.6\bin\EDL\rooting\vbmeta_system.img",
    r"H:\xtcz10check\AllToolBox1.4.6\bin\EDL\rooting\281\vbmeta.img",
    r"H:\xtcz10check\AllToolBox1.4.6\bin\EDL\rooting\281\vbmeta_system.img",
]

for f in files:
    analyze_file(f)
