import struct
import os

abl_path = r'H:\xtcz10check\v1.0.1_dump\abl_v101.img'
author_abl_path = r'H:\xtcz10check\2\250803\abl.img'
results = []

# 1. 解析程序头
results.append('=' * 60)
results.append('程序头解析')
results.append('=' * 60)
f = open(abl_path, 'rb')
f.seek(0x34)  # phoff
for i in range(3):
    ph = f.read(32)
    p_type = struct.unpack_from('<I', ph, 0)[0]
    p_offset = struct.unpack_from('<I', ph, 4)[0]
    p_vaddr = struct.unpack_from('<I', ph, 8)[0]
    p_paddr = struct.unpack_from('<I', ph, 12)[0]
    p_filesz = struct.unpack_from('<I', ph, 16)[0]
    p_memsz = struct.unpack_from('<I', ph, 20)[0]
    p_flags = struct.unpack_from('<I', ph, 24)[0]
    p_align = struct.unpack_from('<I', ph, 28)[0]
    type_name = {1: 'PT_LOAD', 2: 'PT_DYNAMIC', 4: 'PT_NOTE', 6: 'PT_PHDR'}.get(p_type, f'0x{p_type:X}')
    flags_name = ''
    if p_flags & 4: flags_name += 'R'
    if p_flags & 2: flags_name += 'W'
    if p_flags & 1: flags_name += 'X'
    results.append(f'  PH[{i}]: type={type_name} offset=0x{p_offset:X} vaddr=0x{p_vaddr:X} filesz=0x{p_filesz:X} memsz=0x{p_memsz:X} flags={flags_name}')
f.close()

# 2. 列出所有字符串（不分类，全部列出）
results.append('\n' + '=' * 60)
results.append('abl 中全部可打印字符串（>=5字符）')
results.append('=' * 60)
f = open(abl_path, 'rb')
data = f.read()
f.close()

strings = []
current = b''
for i, b in enumerate(data):
    if 32 <= b < 127:
        current += bytes([b])
    else:
        if len(current) >= 5:
            try:
                s = current.decode('ascii')
                strings.append((i - len(current), s))
            except:
                pass
        current = b''
if len(current) >= 5:
    try:
        s = current.decode('ascii')
        strings.append((len(data) - len(current), s))
    except:
        pass

results.append(f'共找到 {len(strings)} 个字符串:')
for offset, s in strings:
    results.append(f'  @0x{offset:06X}: "{s}"')

# 3. 搜索 UTF-16LE 字符串
results.append('\n' + '=' * 60)
results.append('UTF-16LE 字符串搜索')
results.append('=' * 60)
utf16_strings = []
current = []
for i in range(0, len(data) - 1, 2):
    char = data[i] | (data[i+1] << 8)
    if 32 <= char < 127:
        current.append(char)
    else:
        if len(current) >= 4:
            s = ''.join(chr(c) for c in current)
            utf16_strings.append((i - len(current)*2, s))
        current = []
if len(current) >= 4:
    s = ''.join(chr(c) for c in current)
    utf16_strings.append((len(data) - len(current)*2, s))

results.append(f'找到 {len(utf16_strings)} 个 UTF-16 字符串:')
for offset, s in utf16_strings[:30]:
    results.append(f'  @0x{offset:06X}: "{s}"')

# 4. 完整对比 v1.0.1 和作者 abl 的差异
results.append('\n' + '=' * 60)
results.append('v1.0.1 vs 作者 abl 完整差异分析')
results.append('=' * 60)
f1 = open(abl_path, 'rb')
f2 = open(author_abl_path, 'rb')
d1 = f1.read()
d2 = f2.read()
f1.close()
f2.close()

min_len = min(len(d1), len(d2))
diff_regions = []
in_diff = False
diff_start = 0
for i in range(min_len):
    if d1[i] != d2[i]:
        if not in_diff:
            diff_start = i
            in_diff = True
    else:
        if in_diff:
            diff_regions.append((diff_start, i - diff_start))
            in_diff = False
if in_diff:
    diff_regions.append((diff_start, min_len - diff_start))

results.append(f'v1.0.1 大小: {len(d1)}, 作者大小: {len(d2)}')
results.append(f'差异区域数量: {len(diff_regions)}')
total_diff = sum(length for _, length in diff_regions)
results.append(f'差异总字节数: {total_diff}')
for offset, length in diff_regions[:20]:
    v1_bytes = d1[offset:offset+min(length, 32)].hex()
    author_bytes = d2[offset:offset+min(length, 32)].hex()
    results.append(f'  @0x{offset:06X} 长度={length}:')
    results.append(f'    v1.0.1: {v1_bytes}')
    results.append(f'    作者:    {author_bytes}')

# 5. 检查差异区域是否在代码段或数据段
results.append('\n--- 差异区域所在段分析 ---')
# PH[0]: LOAD, 从之前的输出获取
f = open(abl_path, 'rb')
f.seek(0x34)
ph0 = f.read(32)
f.close()
ph0_offset = struct.unpack_from('<I', ph0, 4)[0]
ph0_vaddr = struct.unpack_from('<I', ph0, 8)[0]
ph0_filesz = struct.unpack_from('<I', ph0, 16)[0]
results.append(f'  LOAD段: 文件偏移0x{ph0_offset:X}-0x{ph0_offset+ph0_filesz:X}, 加载地址0x{ph0_vaddr:X}')
for offset, length in diff_regions:
    if ph0_offset <= offset < ph0_offset + ph0_filesz:
        vaddr = ph0_vaddr + (offset - ph0_offset)
        results.append(f'  差异@0x{offset:X} 在LOAD段内, 对应运行地址0x{vaddr:08X}')
    else:
        results.append(f'  差异@0x{offset:X} 在LOAD段外')

output = '\n'.join(results)
out_path = r'H:\xtcz10check\v1.0.1_dump\abl_deep_analysis.txt'
open(out_path, 'w', encoding='utf-8').write(output)
print(f'完成，结果写入 {out_path}')
print(f'字符串数: {len(strings)}, UTF16字符串数: {len(utf16_strings)}, 差异区域: {len(diff_regions)}')
