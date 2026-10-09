#!/usr/bin/env python3
import struct

data = open('unpacked_abl/author/abl_a_pe32_clean.bin', 'rb').read()

target = 0x7539C

print(f'=== 搜索写入 0x{target:x} 的代码 ===')
print()

# 方法1：搜索 ADRP + ADD + STR 指令序列
# ADRP xN, page
# ADD xN, xN, #offset
# STR wM, [xN, #imm12]  或 STR xM, [xN, #imm12]

def decode_adrp(pc):
    instr = struct.unpack_from('<I', data, pc)[0]
    if (instr & 0x9F000000) != 0x90000000:
        return None, None
    immlo = (instr >> 29) & 0x3
    immhi = (instr >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm -= 0x200000
    page_addr = (pc & ~0xFFF) + (imm << 12)
    rd = instr & 0x1F
    return page_addr, rd

found = []
for pc in range(0, len(data) - 12, 4):
    page_addr, reg = decode_adrp(pc)
    if page_addr is None:
        continue
    
    # 下一条指令应该是 ADD
    instr2 = struct.unpack_from('<I', data, pc + 4)[0]
    if (instr2 & 0xFFC00000) != 0x91000000:
        continue
    imm12 = (instr2 >> 10) & 0xFFF
    rn = (instr2 >> 5) & 0x1F
    rd2 = instr2 & 0x1F
    if rn != reg:
        continue
    
    base_addr = page_addr + imm12
    
    # 再下一条指令应该是 STR（写入 base_addr + offset）
    for offset in range(1, 4):
        instr3 = struct.unpack_from('<I', data, pc + offset * 4)[0]
        # STR w (immediate)
        if (instr3 & 0xFFC00000) == 0xB9000000:
            str_imm = ((instr3 >> 10) & 0xFFF) * 4
            str_rn = (instr3 >> 5) & 0x1F
            str_rt = instr3 & 0x1F
            if str_rn == rd2:
                write_addr = base_addr + str_imm
                if write_addr == target:
                    found.append((pc, f'str w{str_rt}, [x{rd2}, #{str_imm}] -> 0x{write_addr:x}'))
        # STR x (immediate)
        elif (instr3 & 0xFFC00000) == 0xF9000000:
            str_imm = ((instr3 >> 10) & 0xFFF) * 8
            str_rn = (instr3 >> 5) & 0x1F
            str_rt = instr3 & 0x1F
            if str_rn == rd2:
                write_addr = base_addr + str_imm
                if write_addr == target:
                    found.append((pc, f'str x{str_rt}, [x{rd2}, #{str_imm}] -> 0x{write_addr:x}'))

print(f'找到 {len(found)} 处写入:')
for pc, desc in found:
    print(f'  0x{pc:x}: {desc}')
    # 打印上下文
    for i in range(-4, 8):
        addr = pc + i*4
        if 0 <= addr < len(data) - 4:
            instr = struct.unpack_from('<I', data, addr)[0]
            marker = ' <--' if i == 0 else ''
            print(f'    0x{addr:x}: {instr:08x}{marker}')
    print()

print()
print('=== 搜索读取 0x75390 基址的代码（可能是初始化函数） ===')
# 搜索引用 0x75390 的 ADRP+ADD
for pc in range(0, len(data) - 8, 4):
    page_addr, reg = decode_adrp(pc)
    if page_addr is None:
        continue
    instr2 = struct.unpack_from('<I', data, pc + 4)[0]
    if (instr2 & 0xFFC00000) != 0x91000000:
        continue
    imm12 = (instr2 >> 10) & 0xFFF
    rn = (instr2 >> 5) & 0x1F
    if rn != reg:
        continue
    addr = page_addr + imm12
    if addr == 0x75390:
        print(f'  0x{pc:x}: adrp+add -> 0x{addr:x} (IsAllowUnlock结构体基址)')
