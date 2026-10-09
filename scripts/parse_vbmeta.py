import struct
import sys

def parse_avb_header(path):
    with open(path, 'rb') as f:
        data = f.read()

    print(f"\n=== {path} ===")
    print(f"文件大小: {len(data)} 字节")

    # AVB 头部（小端）
    magic = data[0:4]
    print(f"Magic: {magic}")

    if magic != b'AVB0':
        print("不是标准 AVB 格式！")
        # 看看开头是什么
        print(f"前 64 字节 hex: {data[:64].hex()}")
        return

    # 解析头部字段
    auth_size = struct.unpack_from('<Q', data, 8)[0]
    aux_size = struct.unpack_from('<Q', data, 16)[0]
    algo = struct.unpack_from('<I', data, 24)[0]
    hash_offset = struct.unpack_from('<Q', data, 28)[0]
    hash_size = struct.unpack_from('<Q', data, 36)[0]
    sig_offset = struct.unpack_from('<Q', data, 44)[0]
    sig_size = struct.unpack_from('<Q', data, 52)[0]
    pubkey_offset = struct.unpack_from('<Q', data, 60)[0]
    pubkey_size = struct.unpack_from('<Q', data, 68)[0]
    desc_offset = struct.unpack_from('<Q', data, 76)[0]
    desc_size = struct.unpack_from('<Q', data, 84)[0]
    rollback = struct.unpack_from('<Q', data, 92)[0]
    flags = struct.unpack_from('<I', data, 100)[0]

    algo_names = {
        0: "NONE",
        1: "SHA256_RSA2048",
        2: "SHA256_RSA4096",
        3: "SHA256_RSA8192",
        4: "SHA512_RSA2048",
        5: "SHA512_RSA4096",
        6: "SHA512_RSA8192",
        7: "SHA256_ECDSA_P256",
        8: "SHA512_ECDSA_P521",
    }

    print(f"算法: {algo_names.get(algo, f'UNKNOWN({algo})')}")
    print(f"Flags: {flags} (0=正常, 1=禁用验证, 2=禁用验证+错误)")
    print(f"Rollback Index: {rollback}")
    print(f"认证数据块大小: {auth_size}")
    print(f"辅助数据块大小: {aux_size}")
    print(f"签名偏移: {sig_offset}, 大小: {sig_size}")
    print(f"公钥偏移: {pubkey_offset}, 大小: {pubkey_size}")
    print(f"描述符偏移: {desc_offset}, 大小: {desc_size}")
    print(f"哈希偏移: {hash_offset}, 大小: {hash_size}")

    # 解析描述符
    if desc_size > 0:
        print(f"\n--- 描述符 ({desc_size} 字节) ---")
        pos = desc_offset
        end = desc_offset + desc_size
        while pos < end:
            if pos + 8 > len(data):
                break
            desc_tag = struct.unpack_from('<Q', data, pos)[0]
            desc_num_bytes = struct.unpack_from('<Q', data, pos+8)[0]
            tag_names = {
                0: "HASHTREE",
                1: "HASH",
                2: "CHAIN_PARTITION",
                3: "ATX_LIB_UNLOCK",
                4: "PROPERTY",
                5: "KERNEL_CMDLINE",
                6: "CHAIN_PARTITION_EXT",
            }
            tag_name = tag_names.get(desc_tag, f"UNKNOWN({desc_tag})")
            print(f"  标签: {tag_name}, 大小: {desc_num_bytes}")

            # 对于 HASH 描述符，读取分区名
            if desc_tag == 1 and desc_num_bytes > 32:
                # HASH 描述符结构：tag(8) + num_bytes(8) + image_size(8) + hash_alg(32) + partition_name(?)
                partition_name = data[pos+56:pos+56+32].split(b'\x00')[0].decode('ascii', errors='replace')
                print(f"    分区名: {partition_name}")

            # 对于 CHAIN_PARTITION，读取分区名
            if desc_tag == 2 and desc_num_bytes > 32:
                partition_name = data[pos+24:pos+24+32].split(b'\x00')[0].decode('ascii', errors='replace')
                print(f"    分区名: {partition_name}")

            pos += 16 + desc_num_bytes
            # 对齐到 8 字节
            if pos % 8 != 0:
                pos += 8 - (pos % 8)

    # 公钥前 32 字节
    if pubkey_size > 0:
        pubkey = data[pubkey_offset:pubkey_offset+min(pubkey_size, 64)]
        print(f"\n公钥前 64 字节: {pubkey.hex()}")

# 解析所有 vbmeta
files = [
    r"H:\xtcz10check\AllToolBox1.4.6\bin\EDL\rooting\vbmeta.img",
    r"H:\xtcz10check\AllToolBox1.4.6\bin\EDL\rooting\vbmeta_system.img",
    r"H:\xtcz10check\AllToolBox1.4.6\bin\EDL\rooting\281\vbmeta.img",
    r"H:\xtcz10check\AllToolBox1.4.6\bin\EDL\rooting\281\vbmeta_system.img",
]

for f in files:
    parse_avb_header(f)
