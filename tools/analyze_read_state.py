#!/usr/bin/env python3
import struct

data = open('unpacked_abl/author/abl_a_pe32_clean.bin', 'rb').read()

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

print('=== 反汇编 0x38d28 (读取当前解锁状态) ===')
print()

for pc in range(0x38d28, 0x38d28 + 0x100, 4):
    instr = struct.unpack_from('<I', data, pc)[0]
    
    desc = ''
    if instr == 0xD65F03C0:
        desc = 'ret'
    elif (instr & 0x9F000000) == 0x90000000:
        addr = decode_adrp_add(pc)
        if addr:
            s = read_string(addr)
            if s and len(s) > 2:
                desc = f'adrp+add -> "{s[:50]}"'
            else:
                desc = f'adrp+add -> 0x{addr:x}'
    elif (instr & 0xFC000000) == 0x94000000:
        imm = instr & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        target = pc + imm * 4
        desc = f'bl 0x{target:x}'
    elif (instr & 0xFFC00000) == 0xB9400000:
        imm12 = ((instr >> 10) & 0xFFF) * 4
        rn = (instr >> 5) & 0x1F
        rt = instr & 0x1F
        desc = f'ldr w{rt}, [x{rn}, #{imm12}]'
    elif (instr & 0xFFC00000) == 0xF9400000:
        imm12 = ((instr >> 10) & 0xFFF) * 8
        rn = (instr >> 5) & 0x1F
        rt = instr & 0x1F
        desc = f'ldr x{rt}, [x{rn}, #{imm12}]'
    elif (instr & 0xFF800000) == 0xAA000000:
        rm = (instr >> 16) & 0x1F
        rn = (instr >> 5) & 0x1F
        rd = instr & 0x1F
        desc = f'mov x{rd}, x{rn}'
    elif (instr & 0xFF800000) == 0x52800000:
        imm = ((instr >> 5) & 0xFFFF) | ((instr >> 29) & 0x3) << 16
        rt = instr & 0x1F
        desc = f'mov w{rt}, #{imm}'
    
    print(f'  0x{pc:x}: {instr:08x}  {desc}')
    
    if instr == 0xD65F03C0:
        print(f'  --- 函数结束 ---')
        break

print()
print('=== 搜索调用 0x38d28 的位置 ===')
target = 0x38d28
for pc in range(0, len(data) - 4, 4):
    instr = struct.unpack_from('<I', data, pc)[0]
    if (instr & 0xFC000000) == 0x94000000:
        imm = instr & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        call_target = pc + imm * 4
        if call_target == target:
            print(f'  0x{pc:x}: bl 0x{target:x}')

print()
print('=== 反汇编 0x16520 附近的桩函数（完整） ===')
for pc in range(0x16510, 0x16560, 4):
    instr = struct.unpack_from('<I', data, pc)[0]
    desc = ''
    if instr == 0xD65F03C0:
        desc = 'ret'
    elif (instr & 0xFF800000) == 0xAA000000:
        rm = (instr >> 16) & 0x1F
        rn = (instr >> 5) & 0x1F
        rd = instr & 0x1F
        desc = f'mov x{rd}, x{rn}'
    elif (instr & 0xFF800000) == 0x52800000:
        imm = ((instr >> 5) & 0xFFFF) | ((instr >> 29) & 0x3) << 16
        rt = instr & 0x1F
        desc = f'mov w{rt}, #{imm}'
    elif (instr & 0xFC000000) == 0x94000000:
        imm = instr & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        t = pc + imm * 4
        desc = f'bl 0x{t:x}'
    print(f'  0x{pc:x}: {instr:08x}  {desc}')
