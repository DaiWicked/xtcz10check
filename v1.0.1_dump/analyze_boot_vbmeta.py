import struct
import hashlib

author_boot = r'H:\xtcz10check\2\250803\boot.img'
author_vbmeta = r'H:\xtcz10check\2\250803\vbmeta.img'
results = []

# 1. 解析作者 boot.img 头部，提取 cmdline
f = open(author_boot, 'rb')
boot = f.read()
f.close()

results.append('=== 作者 boot.img 头部信息 ===')
results.append(f'magic: {boot[:8]}')
# boot header v2:
# 0x00: magic (8)
# 0x08: kernel_size (4)
# 0x0C: kernel_addr (4)
# 0x10: ramdisk_size (4)
# 0x14: ramdisk_addr (4)
# 0x18: second_size (4)
# 0x1C: second_addr (4)
# 0x20: tags_addr (4)
# 0x24: page_size (4)
# 0x28: header_version (4)
# 0x2C: os_version (4)
# 0x30: name (16)
# 0x40: cmdline (512)
# 0x240: id (32)
# 0x260: extra_cmdline (1024)

kernel_size = struct.unpack_from('<I', boot, 8)[0]
ramdisk_size = struct.unpack_from('<I', boot, 16)[0]
page_size = struct.unpack_from('<I', boot, 36)[0]
header_version = struct.unpack_from('<I', boot, 40)[0]
cmdline = boot[0x40:0x40+512].rstrip(b'\x00').decode('ascii', errors='replace')
extra_cmdline = boot[0x260:0x260+1024].rstrip(b'\x00').decode('ascii', errors='replace')

results.append(f'kernel_size: {kernel_size}')
results.append(f'ramdisk_size: {ramdisk_size}')
results.append(f'page_size: {page_size}')
results.append(f'header_version: {header_version}')
results.append(f'cmdline: {cmdline}')
results.append(f'extra_cmdline: {extra_cmdline}')

# 检查 cmdline 中的关键参数
results.append('\n=== cmdline 关键参数检查 ===')
for kw in ['verifiedbootstate', 'vbmeta', 'avb', 'androidboot.verified', 'androidboot.vbmeta', 'buildvariant', 'androidboot.hardware', 'androidboot.bootdevice']:
    if kw in cmdline or kw in extra_cmdline:
        results.append(f'  找到: {kw}')
    else:
        results.append(f'  未找到: {kw}')

# 2. 计算 boot.img 的 SHA256（用于和 vbmeta 哈希描述符对比）
# AVB 计算的是整个分区的哈希，不是只算 kernel
# 但 vbmeta 中的 hash descriptor 包含的是 boot 分区的哈希
boot_sha256 = hashlib.sha256(boot).hexdigest()
results.append(f'\n=== boot.img SHA256 ===')
results.append(f'  整个boot.img SHA256: {boot_sha256}')

# 3. 解析 vbmeta 中的哈希描述符，提取 boot 的哈希
f = open(author_vbmeta, 'rb')
vb = f.read()
f.close()

results.append(f'\n=== vbmeta 哈希描述符分析 ===')
# 描述符从 auth block 起始（偏移256）开始
# hash descriptor 结构（大端）:
# tag (8) = 0
# num_bytes_following (8)
# image_size (8)
# hash_alg (32, 字符串)
# partition_name (变长)
# salt (变长)
# root_digest (变长, = hash_size)
# flags (4)

desc_start = 256  # auth block 起始
# 读取第一个描述符
tag = struct.unpack_from('>Q', vb, desc_start)[0]
num_bytes = struct.unpack_from('>Q', vb, desc_start+8)[0]
results.append(f'  描述符 tag: {tag} (0=hash, 1=hashtree, 2=chain)')
results.append(f'  描述符 num_bytes_following: {num_bytes}')

if tag == 0:  # hash descriptor
    image_size = struct.unpack_from('>Q', vb, desc_start+16)[0]
    hash_alg = vb[desc_start+24:desc_start+24+32].rstrip(b'\x00').decode('ascii', errors='replace')
    results.append(f'  image_size: {image_size} (0x{image_size:X})')
    results.append(f'  hash_alg: {hash_alg}')

    # partition_name 在 hash_alg 之后，以 null 结尾
    name_start = desc_start + 24 + 32
    name_end = vb.find(b'\x00', name_start)
    partition_name = vb[name_start:name_end].decode('ascii', errors='replace')
    results.append(f'  partition_name: {partition_name}')

    # salt 在 partition_name 之后
    # salt 长度 = 32 (SHA256)
    salt_start = name_end + 1
    salt = vb[salt_start:salt_start+32]
    results.append(f'  salt (32字节): {salt.hex()}')

    # root_digest 在 salt 之后
    digest_start = salt_start + 32
    root_digest = vb[digest_start:digest_start+32]
    results.append(f'  root_digest (32字节): {root_digest.hex()}')

    # 计算 boot.img 的实际哈希（AVB 方式：salt + image数据）
    # AVB hash descriptor 的计算方式：SHA256(salt + image_data)
    # 但 image_data 是整个分区（包括填充到 image_size）
    # boot.img 实际大小可能小于 image_size，需要填充
    results.append(f'\n  boot.img 实际大小: {len(boot)}')
    results.append(f'  vbmeta 中 image_size: {image_size}')

    if len(boot) <= image_size:
        # 填充到 image_size
        boot_padded = boot + b'\x00' * (image_size - len(boot))
        # 计算 SHA256(salt + boot_padded)
        computed = hashlib.sha256(salt + boot_padded).digest()
        results.append(f'  计算的 SHA256(salt+boot): {computed.hex()}')
        results.append(f'  vbmeta 中的 root_digest: {root_digest.hex()}')
        if computed == root_digest:
            results.append(f'  *** 哈希匹配！vbmeta 是为这个 boot.img 正确生成的 ***')
        else:
            results.append(f'  *** 哈希不匹配！vbmeta 不是为这个 boot.img 生成的，或者计算方式不同 ***')

# 4. 检查 vbmeta flags
flags = struct.unpack_from('>I', vb, 0x78)[0]
results.append(f'\n=== vbmeta flags ===')
results.append(f'  flags: {flags}')
results.append(f'  bit0 (HASHTREE_DISABLED): {(flags>>0)&1}')
results.append(f'  bit1 (VERIFICATION_DISABLED): {(flags>>1)&1}')
if flags == 0:
    results.append(f'  flags=0: AVB验证和verity形式上都开启')
elif flags == 2:
    results.append(f'  flags=2: AVB验证被禁用 (VERIFICATION_DISABLED)')

# 5. 检查作者 boot.img 中是否有 avb 相关的修改
results.append(f'\n=== boot.img 中 AVB 相关检查 ===')
# 检查 kernel 中是否有 "androidboot.verifiedbootstate"
kernel_start = page_size  # kernel 从第二个 page 开始
kernel_data = boot[kernel_start:kernel_start+kernel_size]
# 搜索 kernel 中的字符串
for kw in [b'verifiedbootstate', b'vbmeta', b'avb_', b'androidboot.bootdevice']:
    pos = kernel_data.find(kw)
    if pos >= 0:
        results.append(f'  kernel中找到 "{kw.decode()}" @0x{pos:X}')
    else:
        results.append(f'  kernel中未找到 "{kw.decode()}"')

output = '\n'.join(results)
out_path = r'H:\xtcz10check\v1.0.1_dump\boot_vbmeta_analysis.txt'
open(out_path, 'w', encoding='utf-8').write(output)
print(f'完成，结果写入 {out_path}')
