import struct
import os

dumpdir = r'H:\xtcz10check\v1.0.1_dump'
results = []

# 1. 分析 persist.img - 检查文件系统类型
f = open(os.path.join(dumpdir, 'persist.img'), 'rb')
# 检查各种偏移的魔术字
f.seek(1024)
ext4_magic = f.read(2)
f.seek(1024)
erofs_magic = f.read(4)
f.seek(0)
f2fs_magic = f.read(4)
# f2fs魔术字在偏移0x400
f.seek(0x400)
f2fs_magic2 = f.read(4)
# 搜索整个文件中的字符串
f.seek(0)
data = f.read(min(32*1024*1024, 1024*1024))  # 读前1MB搜索字符串
f.close()

results.append('=== persist.img 文件系统检测 ===')
results.append(f'  ext4 magic @1024+56: {ext4_magic.hex()} (期望53ef)')
results.append(f'  erofs magic @1024: {erofs_magic.hex()} (期望e2e1f5e0)')
results.append(f'  f2fs magic @0: {f2fs_magic.hex()} (期望1020f5f2)')
results.append(f'  f2fs magic @0x400: {f2fs_magic2.hex()} (期望1020f5f2)')

# 搜索persist中的关键字符串
strings = []
current = b''
for b in data:
    if 32 <= b < 127:
        current += bytes([b])
    else:
        if len(current) >= 6:
            s = current.decode('ascii', errors='replace')
            if any(k in s.lower() for k in ['xtc', 'imoo', 'careme', 'bind', 'parent', 'guard', 'sn', 'serial', 'account', 'lock', 'device', 'user', 'config', 'xml', 'json', 'prop']):
                strings.append(s)
        current = b''
if len(current) >= 6:
    s = current.decode('ascii', errors='replace')
    if any(k in s.lower() for k in ['xtc', 'imoo', 'careme', 'bind', 'parent', 'guard', 'sn', 'serial', 'account', 'lock', 'device', 'user', 'config', 'xml', 'json', 'prop']):
        strings.append(s)

results.append(f'\n  persist前1MB中关键字符串(去重前{len(strings)}个):')
seen = set()
for s in strings:
    if s not in seen and len(s) < 200:
        seen.add(s)
        results.append(f'    "{s}"')
        if len(seen) > 50:
            results.append('    ... (更多省略)')
            break

# 2. 分析 xtcdata.img - 已经确认是ext4，尝试读取根目录
results.append('\n=== xtcdata.img (ext4) 分析 ===')
f = open(os.path.join(dumpdir, 'xtcdata.img'), 'rb')
# 读取ext4超级块
f.seek(1024)
sb = f.read(256)
# ext4超级块字段
s_inodes_count = struct.unpack_from('<I', sb, 0)[0]
s_blocks_count_lo = struct.unpack_from('<I', sb, 4)[0]
s_block_size = 1024 << struct.unpack_from('<I', sb, 24)[0]
s_blocks_per_group = struct.unpack_from('<I', sb, 32)[0]
s_inodes_per_group = struct.unpack_from('<I', sb, 40)[0]
s_magic = struct.unpack_from('<H', sb, 56)[0]
s_volume_name = sb[120:136].rstrip(b'\x00').decode('ascii', errors='replace')
s_last_mounted = sb[136:200].rstrip(b'\x00').decode('ascii', errors='replace')
f.close()

results.append(f'  ext4 魔术字: 0x{s_magic:04X} (53EF=ext4)')
results.append(f'  块大小: {s_block_size}')
results.append(f'  inode总数: {s_inodes_count}')
results.append(f'  块总数: {s_blocks_count_lo}')
results.append(f'  卷标: "{s_volume_name}"')
results.append(f'  最后挂载点: "{s_last_mounted}"')

# 搜索xtcdata前2MB中的关键字符串
f = open(os.path.join(dumpdir, 'xtcdata.img'), 'rb')
data = f.read(2*1024*1024)
f.close()

strings2 = []
current = b''
for b in data:
    if 32 <= b < 127:
        current += bytes([b])
    else:
        if len(current) >= 8:
            s = current.decode('ascii', errors='replace')
            if any(k in s.lower() for k in ['xtc', 'imoo', 'careme', 'bind', 'parent', 'guard', 'account', 'lock', 'config', 'xml', 'json', 'prop', 'apk', 'database', 'db']):
                strings2.append(s)
        current = b''
if len(current) >= 8:
    s = current.decode('ascii', errors='replace')
    if any(k in s.lower() for k in ['xtc', 'imoo', 'careme', 'bind', 'parent', 'guard', 'account', 'lock', 'config', 'xml', 'json', 'prop', 'apk', 'database', 'db']):
        strings2.append(s)

results.append(f'\n  xtcdata前2MB中关键字符串(去重前{len(strings2)}个):')
seen2 = set()
for s in strings2:
    if s not in seen2 and len(s) < 200:
        seen2.add(s)
        results.append(f'    "{s}"')
        if len(seen2) > 60:
            results.append('    ... (更多省略)')
            break

# 3. 分析 misc.img 中的 ffbm-02
results.append('\n=== misc.img 详细分析 ===')
f = open(os.path.join(dumpdir, 'misc.img'), 'rb')
misc_data = f.read(4096)
f.close()
results.append(f'  开头8字节: {misc_data[:8].hex()} = "{misc_data[:8].rstrip(b"\x00").decode("ascii", errors="replace")}"')
results.append(f'  "ffbm-02" = Qualcomm Factory Fast Boot Mode 命令')
results.append(f'  这是进入工厂/QMMI测试模式的启动命令')
results.append(f'  作者v2.8.1方案中misc写的是"boot-fastboot"(13字节)，而v1.0.1当前是"ffbm-02"')

output = '\n'.join(results)
open(os.path.join(dumpdir, 'deep_analysis.txt'), 'w', encoding='utf-8').write(output)
print('done')
