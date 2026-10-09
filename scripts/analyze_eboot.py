import struct

path = r"H:\xtcz10check\AllToolBox1.4.6\bin\EDL\rooting\eboot.img"
with open(path, 'rb') as f:
    data = f.read()

print(f"文件大小: {len(data)} 字节 ({len(data)/1024/1024:.1f} MB)")

# 搜索各种魔数
magics = [b'ANDROID!', b'AVB0', b'\x1f\x8b', b'BZh', b'\xfd7zXZ', b'\x89PNG', b'ELF']
for magic in magics:
    pos = data.find(magic)
    if pos >= 0:
        print(f"找到 {magic} 在偏移 {pos} (0x{pos:x})")
    else:
        print(f"未找到 {magic}")

# 统计非零字节
non_zero = sum(1 for b in data if b != 0)
print(f"\n非零字节数: {non_zero} ({non_zero/len(data)*100:.2f}%)")
print(f"零字节数: {len(data) - non_zero} ({(len(data)-non_zero)/len(data)*100:.2f}%)")

# 找到第一个非零字节
first_non_zero = next((i for i, b in enumerate(data) if b != 0), -1)
print(f"第一个非零字节偏移: {first_non_zero} (0x{first_non_zero:x})")

# 找到最后一个非零字节
last_non_zero = max((i for i, b in enumerate(data) if b != 0), default=-1)
print(f"最后一个非零字节偏移: {last_non_zero} (0x{last_non_zero:x})")

# 如果有内容，看看第一个非零区域
if first_non_zero >= 0:
    print(f"\n=== 第一个非零区域 (偏移 {first_non_zero}) ===")
    start = max(0, first_non_zero - 16)
    for i in range(start, min(start + 128, len(data)), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        print(f'{i:08x}: {hex_part:<48} {ascii_part}')

# 对比 boot.img
boot_path = r"H:\xtcz10check\AllToolBox1.4.6\bin\EDL\rooting\boot.img"
with open(boot_path, 'rb') as f:
    boot_data = f.read()
print(f"\n=== boot.img 对比 ===")
print(f"boot.img 大小: {len(boot_data)} 字节 ({len(boot_data)/1024/1024:.1f} MB)")
print(f"boot.img 前 16 字节: {boot_data[:16].hex()}")
print(f"boot.img 前 8 字节 ascii: {boot_data[:8]}")
