#!/usr/bin/env python3
import struct

data = open('unpacked_abl/v1.0.1/abl_pe32_clean.bin', 'rb').read()

def read_string(addr):
    if addr >= len(data):
        return None
    end = addr
    while end < len(data) and data[end] != 0:
        end += 1
    try:
        return data[addr:end].decode('ascii', errors='replace')
    except:
        return None

print('=== 完整命令表 (从0x4f228开始) ===')
print()

# 命令表从0x4f228开始，每个条目16字节（8字节字符串指针 + 8字节函数指针）
# 实际上是两个u32，高32位为0
table_start = 0x4f228
for i in range(30):
    offset = table_start + i * 16
    if offset + 8 > len(data):
        break
    str_ptr = struct.unpack_from('<I', data, offset)[0]
    func_ptr = struct.unpack_from('<I', data, offset + 8)[0]
    
    if str_ptr == 0 and func_ptr == 0:
        print(f'  [{i}] 结束标记')
        break
    
    cmd_name = read_string(str_ptr) if str_ptr else 'NULL'
    print(f'  [{i}] 0x{str_ptr:08x} -> 0x{func_ptr:08x}  "{cmd_name}"')

print()
print('=== 搜索 0x32300 函数的调用者 ===')
# 搜索bl 0x32300
for pc in range(0, len(data) - 4, 4):
    instr = struct.unpack_from('<I', data, pc)[0]
    if (instr & 0xFC000000) == 0x94000000:
        imm = instr & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        target = pc + imm * 4
        if 0x322f0 <= target <= 0x32310:
            print(f'  0x{pc:x}: bl 0x{target:x}')

print()
print('=== 搜索引用 "frp" 字符串的代码 ===')
import re
# 搜索ASCII "frp"
for m in re.finditer(b'frp\x00', data):
    print(f'  "frp" @ 0x{m.start():x}')
    # 搜索引用这个地址的ADRP+ADD
    target = m.start()
    for pc in range(max(0, target-0x100000), min(len(data)-8, target+0x100000), 4):
        instr1 = struct.unpack_from('<I', data, pc)[0]
        instr2 = struct.unpack_from('<I', data, pc + 4)[0]
        if (instr1 & 0x9F000000) == 0x90000000 and (instr2 & 0xFFC00000) == 0x91000000:
            immlo = (instr1 >> 29) & 0x3
            immhi = (instr1 >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & 0x100000:
                imm -= 0x200000
            page_addr = (pc & ~0xFFF) + (imm << 12)
            imm12 = (instr2 >> 10) & 0xFFF
            addr = page_addr + imm12
            if addr == target:
                print(f'    引用 @ 0x{pc:x}')
