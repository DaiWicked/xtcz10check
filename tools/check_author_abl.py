#!/usr/bin/env python3
import struct
import re

# 检查作者abl
data = open('unpacked_abl/author/abl_a_pe32_clean.bin', 'rb').read()

print('=== 作者abl中搜索 IsAllowUnlock ===')
matches = [(m.start(), m.group().decode('ascii', errors='replace')) for m in re.finditer(b'IsAllowUnlock[^\x00]*', data)]
print(f'找到 {len(matches)} 处:')
for offset, s in matches:
    print(f'  +0x{offset:x}: {s}')

print()
print('=== 作者abl中搜索 oem device-info 命令表 ===')
# 搜索命令表
for m in re.finditer(b'oem device-info\x00', data):
    str_addr = m.start()
    print(f'"oem device-info" @ 0x{str_addr:x}')
    # 搜索引用这个地址的表
    target_bytes = struct.pack('<I', str_addr)
    pos = data.find(target_bytes)
    if pos != -1:
        func_ptr = struct.unpack_from('<I', data, pos + 8)[0]
        print(f'  命令表 @ 0x{pos:x}, 处理函数 = 0x{func_ptr:x}')

print()
print('=== 作者abl中搜索 0x32300 附近的函数调用 ===')
# 搜索bl到0x32300附近的调用
target_func = 0x32300
count = 0
for pc in range(0, len(data) - 4, 4):
    instr = struct.unpack_from('<I', data, pc)[0]
    if (instr & 0xFC000000) == 0x94000000:
        imm = instr & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        target = pc + imm * 4
        if abs(target - target_func) < 0x100:
            print(f'  0x{pc:x}: bl 0x{target:x}')
            count += 1
            if count > 10:
                break
