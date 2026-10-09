import struct
import os

abl_path = r'H:\xtcz10check\v1.0.1_dump\abl_v101.img'
author_abl_path = r'H:\xtcz10check\2\250803\abl.img'
results = []

f = open(abl_path, 'rb')
data = f.read()
f.close()

results.append('=' * 60)
results.append('abl 文件布局分析')
results.append('=' * 60)
results.append(f'文件总大小: {len(data)} (0x{len(data):X})')
results.append(f'PH[0]: 0x0-0x94 (ELF头, 明文)')
results.append(f'PH[1]: 0x1000-0x25000 (代码段, 0x24000={0x24000}字节, 加密)')
results.append(f'PH[2]: 0x25000-0x26060 (0x1060={0x1060}字节, 未知)')
results.append(f'文件剩余: 0x26060-0x{len(data):X} ({len(data)-0x26060}字节, 未知)')

# 检查 PH[2] 内容 (0x25000)
results.append('\n' + '=' * 60)
results.append('PH[2] 区域内容 (0x25000-0x26060)')
results.append('=' * 60)
ph2_data = data[0x25000:0x26060]
# 十六进制输出前256字节
for i in range(0, min(256, len(ph2_data)), 16):
    hex_part = ' '.join(f'{b:02X}' for b in ph2_data[i:i+16])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ph2_data[i:i+16])
    results.append(f'  {0x25000+i:06X}: {hex_part:<48s} {ascii_part}')

# 搜索PH[2]中的可打印字符串
strings = []
current = b''
for i, b in enumerate(ph2_data):
    if 32 <= b < 127:
        current += bytes([b])
    else:
        if len(current) >= 4:
            strings.append((0x25000+i-len(current), current.decode('ascii', errors='replace')))
        current = b''
results.append(f'\nPH[2] 中的字符串:')
for offset, s in strings:
    results.append(f'  @0x{offset:06X}: "{s}"')

# 检查文件末尾内容
results.append('\n' + '=' * 60)
results.append('文件末尾区域 (最后2048字节)')
results.append('=' * 60)
tail_data = data[-2048:]
for i in range(0, len(tail_data), 16):
    offset = len(data) - 2048 + i
    hex_part = ' '.join(f'{b:02X}' for b in tail_data[i:i+16])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in tail_data[i:i+16])
    results.append(f'  {offset:06X}: {hex_part:<48s} {ascii_part}')

# 检查文件末尾的字符串
tail_strings = []
current = b''
for i, b in enumerate(tail_data):
    if 32 <= b < 127:
        current += bytes([b])
    else:
        if len(current) >= 4:
            tail_strings.append((len(data)-2048+i-len(current), current.decode('ascii', errors='replace')))
        current = b''
results.append(f'\n文件末尾中的字符串:')
for offset, s in tail_strings:
    results.append(f'  @0x{offset:06X}: "{s}"')

# 检查高通签名 (通常在文件末尾，有特定结构)
results.append('\n' + '=' * 60)
results.append('高通签名检测')
results.append('=' * 60)
# 高通签名魔术字
sig_magics = [
    (b'\x48\x44\x52\x21', 'HDR!'),
    (b'\x44\x42\x45\x21', 'DBE!'),
    (b'\x44\x42\x45\x20', 'DBE '),
    (b'\x4C\x4C\x4C\x4C', 'LLLL'),
    (b'\x53\x49\x47\x21', 'SIG!'),
]
for magic, name in sig_magics:
    pos = data.rfind(magic)
    if pos >= 0:
        results.append(f'  找到 {name} ({magic.hex()}) @0x{pos:X}')
        # 显示周围内容
        start = max(0, pos-16)
        end = min(len(data), pos+64)
        results.append(f'  周围: {data[start:end].hex()}')

# 检查 ELF 头之后 0x94-0x1000 之间的内容
results.append('\n' + '=' * 60)
results.append('ELF头和代码段之间 (0x94-0x1000)')
results.append('=' * 60)
gap_data = data[0x94:0x1000]
non_zero = sum(1 for b in gap_data if b != 0)
results.append(f'  大小: {len(gap_data)} 字节, 非零字节: {non_zero}')
if non_zero > 0:
    for i in range(0, len(gap_data), 16):
        if any(b != 0 for b in gap_data[i:i+16]):
            hex_part = ' '.join(f'{b:02X}' for b in gap_data[i:i+16])
            results.append(f'  {0x94+i:06X}: {hex_part}')

# 和作者abl对比文件末尾
results.append('\n' + '=' * 60)
results.append('v1.0.1 vs 作者 abl 文件末尾对比')
results.append('=' * 60)
fa = open(author_abl_path, 'rb')
adata = fa.read()
fa.close()
results.append(f'  v1.0.1 末尾64字节: {data[-64:].hex()}')
results.append(f'  作者 末尾64字节:   {adata[-64:].hex()}')
# 找最后一个差异点
last_diff = -1
for i in range(min(len(data), len(adata))-1, -1, -1):
    if data[i] != adata[i]:
        last_diff = i
        break
results.append(f'  最后一个差异字节 @0x{last_diff:X}')
if last_diff >= 0:
    results.append(f'  v1.0.1: ...{data[max(0,last_diff-8):last_diff+8].hex()}')
    results.append(f'  作者:   ...{adata[max(0,last_diff-8):last_diff+8].hex()}')

output = '\n'.join(results)
out_path = r'H:\xtcz10check\v1.0.1_dump\abl_layout_analysis.txt'
open(out_path, 'w', encoding='utf-8').write(output)
print(f'完成，结果写入 {out_path}')
