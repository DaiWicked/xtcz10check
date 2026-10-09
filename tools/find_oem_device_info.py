#!/usr/bin/env python3
import struct

data = open('unpacked_abl/v1.0.1/abl_pe32_clean.bin', 'rb').read()

def decode_adrp_add(pc):
    if pc + 8 > len(data):
        return None
    instr1 = struct.unpack_from('<I', data, pc)[0]
    instr2 = struct.unpack_from('<I', data, pc + 4)[0]
    if (instr1 & 0x9F000000) != 0x90000000:
        return None
    if (instr2 & 0xFFC00000) != 0x91000000:
        return None
    immlo = (instr1 >> 29) & 0x3
    immhi = (instr1 >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm -= 0x200000
    page_addr = (pc & ~0xFFF) + (imm << 12)
    imm12 = (instr2 >> 10) & 0xFFF
    return page_addr + imm12

def find_string_refs(target_addr, search_range=0x100000):
    """搜索引用指定地址的 ADRP+ADD 指令对"""
    refs = []
    start = max(0, target_addr - search_range)
    end = min(len(data) - 8, target_addr + search_range)
    for pc in range(start, end, 4):
        addr = decode_adrp_add(pc)
        if addr == target_addr:
            refs.append(pc)
    return refs

print('=== 搜索 "oem device-info" (0x4e8f6) 的引用者 ===')
refs = find_string_refs(0x4e8f6)
print(f'找到 {len(refs)} 处引用:')
for pc in refs:
    print(f'  PC=0x{pc:x}')
    # 打印上下文
    for i in range(-6, 10):
        addr = pc + i*4
        if 0 <= addr < len(data) - 4:
            instr = struct.unpack_from('<I', data, addr)[0]
            marker = ' <--' if i == 0 else ''
            print(f'    0x{addr:x}: {instr:08x}{marker}')
    print()

print('=== 搜索 "device-info" (0x4e8fa) 的引用者 ===')
refs2 = find_string_refs(0x4e8fa)
print(f'找到 {len(refs2)} 处引用:')
for pc in refs2[:5]:
    print(f'  PC=0x{pc:x}')

print()
print('=== 搜索 "IsAllowUnlock is %d" (0x4eaa7) 的引用者 ===')
refs3 = find_string_refs(0x4eaa7)
print(f'找到 {len(refs3)} 处引用:')
for pc in refs3:
    print(f'  PC=0x{pc:x}')
    # 往前找函数开头
    for func_start in range(pc, max(0, pc-0x200), -4):
        instr = struct.unpack_from('<I', data, func_start)[0]
        if (instr & 0xFFC003FF) == 0xA98003E0:  # stp x29,x30,[sp,#-N]!
            print(f'  函数开头可能在: 0x{func_start:x}')
            break
