import os
import struct

dumpdir = r'H:\xtcz10check\v1.0.1_dump'
results = []

def hexdump(data, start=0, length=64):
    lines = []
    for i in range(0, min(length, len(data)), 16):
        hex_part = ' '.join(f'{b:02X}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        lines.append(f'  {start+i:08X}: {hex_part:<48s} {ascii_part}')
    return '\n'.join(lines)

def analyze_file(filepath):
    name = os.path.basename(filepath)
    size = os.path.getsize(filepath)
    f = open(filepath, 'rb')
    head = f.read(256)
    f.seek(0)
    # 读取前4KB用于字符串搜索
    first4k = f.read(4096)
    f.close()

    lines = [f'=== {name} ({size} bytes, {size/1024:.1f} KB) ===']
    lines.append(f'前256字节:')
    lines.append(hexdump(head, 0, 256))

    # 搜索可打印字符串
    strings = []
    current = b''
    for b in first4k:
        if 32 <= b < 127:
            current += bytes([b])
        else:
            if len(current) >= 4:
                strings.append(current.decode('ascii', errors='replace'))
            current = b''
    if len(current) >= 4:
        strings.append(current.decode('ascii', errors='replace'))

    if strings:
        lines.append(f'\n前4KB中的可打印字符串(>=4字符):')
        for s in strings[:30]:
            lines.append(f'  "{s}"')

    # 检查文件类型魔术字
    if head[:4] == b'\x53\xEF':
        lines.append('\n文件类型: ext4 superblock magic (但在偏移0，可能是ext4)')
    elif head[1080:1082] == b'\x53\xEF' and size > 1082:
        lines.append('\n文件类型: ext4 (magic @1080)')
    elif head[:4] == b'AVB0':
        lines.append('\n文件类型: Android Verified Boot metadata')
    elif head[:4] == b'ANDROID!':
        lines.append('\n文件类型: Android boot image')
    elif head[:4] == b'\x7fELF':
        lines.append('\n文件类型: ELF binary')
    elif head[:8] == b'boot-fas':
        lines.append('\n文件类型: misc boot command (boot-fastboot)')

    # 检查是否全零
    non_zero = sum(1 for b in head if b != 0)
    if non_zero == 0:
        lines.append('\n注意: 前256字节全零')

    lines.append('')
    return '\n'.join(lines)

for fn in ['misc.img', 'devinfo.img', 'xtcinfo.img', 'persist.img']:
    path = os.path.join(dumpdir, fn)
    if os.path.exists(path):
        results.append(analyze_file(path))

# xtcdata.img太大，只分析头部
path = os.path.join(dumpdir, 'xtcdata.img')
if os.path.exists(path):
    size = os.path.getsize(path)
    f = open(path, 'rb')
    head = f.read(512)
    f.close()
    lines = [f'=== xtcdata.img ({size} bytes, {size/1024/1024:.1f} MB) ===']
    lines.append(f'前512字节:')
    lines.append(hexdump(head, 0, 512))
    # 检查ext4
    if size > 1082:
        f = open(path, 'rb')
        f.seek(1080)
        magic = f.read(2)
        f.close()
        if magic == b'\x53\xEF':
            lines.append('\n文件类型: ext4 (magic 53EF @1080)')
    results.append('\n'.join(lines))

output = '\n'.join(results)
open(os.path.join(dumpdir, 'analysis_result.txt'), 'w').write(output)
print('done')
