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

print('=== 作者abl 0x27040 函数（第5个打印函数） ===')
print()

for pc in range(0x27040, 0x27040 + 0x100, 4):
    instr = struct.unpack_from('<I', data, pc)[0]
    
    desc = ''
    if instr == 0xD65F03C0:
        desc = 'ret'
    elif (instr & 0x9F000000) == 0x90000000:
        addr = decode_adrp_add(pc)
        if addr:
            s = read_string(addr)
            if s and len(s) > 2:
                desc = f'adrp+add -> "{s}"'
            else:
                desc = f'adrp+add -> 0x{addr:x}'
    elif (instr & 0xFC000000) == 0x94000000:
        imm = instr & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        target = pc + imm * 4
        desc = f'bl 0x{target:x}'
    
    marker = ''
    if 'IsAllowUnlock' in desc or 'unlock' in desc.lower():
        marker = ' ★'
    
    print(f'  0x{pc:x}: {instr:08x}  {desc}{marker}')
    
    if instr == 0xD65F03C0:
        break

print()
print('=== 原版abl对应的第5个打印函数 0x25948 ===')
print()

data2 = open('unpacked_abl/v1.0.1/abl_pe32_clean.bin', 'rb').read()

def decode_adrp_add2(pc):
    if pc + 8 > len(data2):
        return None
    instr1 = struct.unpack_from('<I', data2, pc)[0]
    instr2 = struct.unpack_from('<I', data2, pc + 4)[0]
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

def read_string2(addr):
    if addr >= len(data2):
        return None
    end = addr
    while end < len(data2) and data2[end] != 0:
        end += 1
    try:
        return data2[addr:end].decode('ascii', errors='replace')
    except:
        return None

for pc in range(0x25948, 0x25948 + 0x100, 4):
    instr = struct.unpack_from('<I', data2, pc)[0]
    
    desc = ''
    if instr == 0xD65F03C0:
        desc = 'ret'
    elif (instr & 0x9F000000) == 0x90000000:
        addr = decode_adrp_add2(pc)
        if addr:
            s = read_string2(addr)
            if s and len(s) > 2:
                desc = f'adrp+add -> "{s}"'
            else:
                desc = f'adrp+add -> 0x{addr:x}'
    elif (instr & 0xFC000000) == 0x94000000:
        imm = instr & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        target = pc + imm * 4
        desc = f'bl 0x{target:x}'
    
    marker = ''
    if 'IsAllowUnlock' in desc or 'unlock' in desc.lower():
        marker = ' ★'
    
    print(f'  0x{pc:x}: {instr:08x}  {desc}{marker}')
    
    if instr == 0xD65F03C0:
        break
