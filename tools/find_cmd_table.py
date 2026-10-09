#!/usr/bin/env python3
import struct

data = open('unpacked_abl/v1.0.1/abl_pe32_clean.bin', 'rb').read()

# 命令字符串区域
cmd_strings = {
    0x4e894: "oem enable-charger-screen",
    0x4e8ae: "oem disable-charger-screen",
    0x4e8c9: "oem off-mode-charge",
    0x4e8dd: "oem select-display-panel",
    0x4e8f6: "oem device-info",
}

print("=== 命令字符串区域 ===")
for addr, name in sorted(cmd_strings.items()):
    print(f"  0x{addr:x}: {name}")

print()
print("=== 搜索包含这些字符串地址的表（命令表） ===")

# 搜索包含这些地址的区域
# 命令表通常是: (char* name, void* handler) 或 (void* handler, char* name)
target_addrs = set(cmd_strings.keys())

# 在整个文件中搜索这些地址作为小端u32或u64出现的位置
for target in sorted(target_addrs):
    target_bytes = struct.pack('<I', target)
    positions = []
    start = 0
    while True:
        pos = data.find(target_bytes, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1
    print(f"  0x{target:x} ({cmd_strings[target]}): 找到 {len(positions)} 处引用")
    for p in positions[:5]:
        # 检查是否在一个表结构中（前后有其他指针）
        print(f"    @0x{p:x}")
        # 打印周围的8个指针
        for i in range(-4, 6):
            addr = p + i*8
            if 0 <= addr < len(data) - 8:
                val1 = struct.unpack_from('<I', data, addr)[0]
                val2 = struct.unpack_from('<I', data, addr+4)[0]
                marker = ' <--' if i == 0 else ''
                # 检查是否是有效的代码地址或字符串地址
                desc = ''
                if val1 in cmd_strings:
                    desc = f'-> "{cmd_strings[val1]}"'
                elif 0x1000 < val1 < 0x80000:
                    desc = '-> code?'
                print(f"      +{i*8:+d}: 0x{val1:08x} 0x{val2:08x} {desc}{marker}")
    print()
