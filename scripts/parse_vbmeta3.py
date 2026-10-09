import struct

def parse_avb(path):
    with open(path, 'rb') as f:
        data = f.read()

    print(f"\n{'='*60}")
    print(f"文件: {path}")
    print(f"大小: {len(data)} 字节")

    if data[:4] != b'AVB0':
        print("不是 AVB0 格式，可能有签名头")
        # 搜索 AVB0
        pos = data.find(b'AVB0')
        if pos >= 0:
            print(f"在偏移 {pos} 找到 AVB0")
            data = data[pos:]
        else:
            return

    # AVB 头部（正确偏移）
    magic = data[0:4]
    major = struct.unpack_from('<I', data, 4)[0]
    minor = struct.unpack_from('<I', data, 8)[0]
    auth_size = struct.unpack_from('<Q', data, 12)[0]
    aux_size = struct.unpack_from('<Q', data, 20)[0]
    algo = struct.unpack_from('<I', data, 28)[0]
    hash_offset = struct.unpack_from('<Q', data, 32)[0]
    hash_size = struct.unpack_from('<Q', data, 40)[0]
    sig_offset = struct.unpack_from('<Q', data, 48)[0]
    sig_size = struct.unpack_from('<Q', data, 56)[0]
    pubkey_offset = struct.unpack_from('<Q', data, 64)[0]
    pubkey_size = struct.unpack_from('<Q', data, 72)[0]
    pubkey_meta_offset = struct.unpack_from('<Q', data, 80)[0]
    pubkey_meta_size = struct.unpack_from('<Q', data, 88)[0]
    desc_offset = struct.unpack_from('<Q', data, 96)[0]
    desc_size = struct.unpack_from('<Q', data, 104)[0]
    rollback = struct.unpack_from('<Q', data, 112)[0]
    flags = struct.unpack_from('<I', data, 120)[0]
    release = data[128:176].split(b'\x00')[0].decode('ascii', errors='replace')

    algo_names = {
        0: "NONE (未签名)",
        1: "SHA256_RSA2048",
        2: "SHA256_RSA4096",
        3: "SHA256_RSA8192",
        4: "SHA512_RSA2048",
        5: "SHA512_RSA4096",
        6: "SHA512_RSA8192",
        7: "SHA256_ECDSA_P256",
        8: "SHA512_ECDSA_P521",
    }

    print(f"\nMagic: {magic.decode()}")
    print(f"AVB 版本: {major}.{minor}")
    print(f"Release: {release}")
    print(f"算法: {algo_names.get(algo, f'UNKNOWN({algo})')}")
    print(f"Flags: {flags}")
    if flags == 0:
        print("  → 正常验证模式")
    elif flags == 1:
        print("  → ★ 禁用哈希验证（允许修改分区）")
    elif flags == 2:
        print("  → 禁用验证 + 错误")
    elif flags == 3:
        print("  → ★ 完全禁用验证")
    print(f"Rollback Index: {rollback}")
    print(f"\n认证数据块大小: {auth_size}")
    print(f"辅助数据块大小: {aux_size}")
    print(f"签名: 偏移={sig_offset}, 大小={sig_size}")
    print(f"公钥: 偏移={pubkey_offset}, 大小={pubkey_size}")
    print(f"描述符: 偏移={desc_offset}, 大小={desc_size}")

    # 解析描述符
    if desc_size > 0:
        print(f"\n--- 描述符 ({desc_size} 字节) ---")
        pos = desc_offset
        end = desc_offset + desc_size
        count = 0
        while pos + 16 <= end and count < 20:
            desc_tag = struct.unpack_from('<Q', data, pos)[0]
            desc_num_bytes = struct.unpack_from('<Q', data, pos+8)[0]
            tag_names = {
                0: "HASHTREE", 1: "HASH", 2: "CHAIN_PARTITION",
                3: "ATX_LIB_UNLOCK", 4: "PROPERTY", 5: "KERNEL_CMDLINE",
                6: "CHAIN_PARTITION_EXT",
            }
            tag_name = tag_names.get(desc_tag, f'UNKNOWN({desc_tag})')

            info = f"  [{count}] {tag_name}: size={desc_num_bytes}"

            # HASH 描述符：分区名在偏移 56
            if desc_tag == 1 and desc_num_bytes >= 56:
                pname = data[pos+56:pos+88].split(b'\x00')[0].decode('ascii', errors='replace')
                info += f", partition={pname}"

            # CHAIN_PARTITION：分区名在偏移 24
            if desc_tag == 2 and desc_num_bytes >= 24:
                pname = data[pos+24:pos+56].split(b'\x00')[0].decode('ascii', errors='replace')
                info += f", partition={pname}"

            # PROPERTY 描述符
            if desc_tag == 4 and desc_num_bytes >= 16:
                key_len = struct.unpack_from('<I', data, pos+16)[0]
                val_len = struct.unpack_from('<I', data, pos+20)[0]
                if key_len > 0 and key_len < 256:
                    key = data[pos+24:pos+24+key_len].split(b'\x00')[0].decode('ascii', errors='replace')
                    info += f", key={key}"

            print(info)
            pos += 16 + desc_num_bytes
            if pos % 8 != 0:
                pos += 8 - (pos % 8)
            count += 1

    # 公钥信息
    if pubkey_size > 0 and pubkey_offset + pubkey_size <= len(data):
        pubkey = data[pubkey_offset:pubkey_offset+pubkey_size]
        print(f"\n公钥前 32 字节: {pubkey[:32].hex()}")
        print(f"公钥大小: {pubkey_size} 字节")
        # RSA 公钥通常以 ASN.1 格式 30 82 开头
        if pubkey[:2] == b'\x30\x82':
            print("→ 看起来是 RSA 公钥 (ASN.1 DER 格式)")

files = [
    r"H:\xtcz10check\AllToolBox1.4.6\bin\EDL\rooting\vbmeta.img",
    r"H:\xtcz10check\AllToolBox1.4.6\bin\EDL\rooting\vbmeta_system.img",
]

for f in files:
    parse_avb(f)
