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

print('=== 核心函数 0x387F4 (flashing unlock/lock 通用处理) ===')
print()

func_start = 0x387f4
for pc in range(func_start, func_start + 0x400, 4):
    instr = struct.unpack_from('<I', data, pc)[0]
    
    desc = ''
    if instr == 0xD65F03C0:
        desc = 'ret'
    elif (instr & 0xFFC003FF) == 0xA98003E0:
        desc = 'stp x29,x30,[sp,#-N]!'
    elif (instr & 0xFF8003FF) == 0xD10003FF:
        desc = 'sub sp,sp,#N'
    elif (instr & 0xFFC003FF) == 0xA8C003E0:
        desc = 'ldp x29,x30,[sp],#N'
    elif (instr & 0x9F000000) == 0x90000000:
        addr = decode_adrp_add(pc)
        if addr:
            s = read_string(addr)
            if s and len(s) > 2:
                desc = f'adrp+add -> "{s[:60]}"'
            else:
                desc = f'adrp+add -> 0x{addr:x}'
    elif (instr & 0xFC000000) == 0x94000000:
        imm = instr & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        target = pc + imm * 4
        desc = f'bl 0x{target:x}'
    elif (instr & 0xFF000000) == 0x54000000:
        imm = (instr >> 5) & 0x7FFF
        if imm & 0x4000:
            imm -= 0x8000
        target = pc + imm * 4
        cond = instr & 0xF
        cond_names = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        desc = f'b.{cond_names[cond]} 0x{target:x}'
    elif (instr & 0xFC000000) == 0x14000000:
        imm = instr & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        target = pc + imm * 4
        desc = f'b 0x{target:x}'
    elif (instr & 0xFFC00000) == 0xB9400000:
        imm12 = ((instr >> 10) & 0xFFF) * 4
        rn = (instr >> 5) & 0x1F
        rt = instr & 0x1F
        desc = f'ldr w{rt}, [x{rn}, #{imm12}]'
    elif (instr & 0xFFC00000) == 0xB9000000:
        imm12 = ((instr >> 10) & 0xFFF) * 4
        rn = (instr >> 5) & 0x1F
        rt = instr & 0x1F
        desc = f'str w{rt}, [x{rn}, #{imm12}]'
    elif (instr & 0xFFC00000) == 0xF9400000:
        imm12 = ((instr >> 10) & 0xFFF) * 8
        rn = (instr >> 5) & 0x1F
        rt = instr & 0x1F
        desc = f'ldr x{rt}, [x{rn}, #{imm12}]'
    elif (instr & 0xFFC00000) == 0xF9000000:
        imm12 = ((instr >> 10) & 0xFFF) * 8
        rn = (instr >> 5) & 0x1F
        rt = instr & 0x1F
        desc = f'str x{rt}, [x{rn}, #{imm12}]'
    elif (instr & 0x7F800000) == 0x71000000:
        desc = 'subs w'
    elif (instr & 0x7F800000) == 0x6B000000:
        desc = 'cmp w'
    elif (instr & 0xFF800000) == 0x52800000:
        imm = ((instr >> 5) & 0xFFFF) | ((instr >> 29) & 0x3) << 16
        rt = instr & 0x1F
        desc = f'mov w{rt}, #{imm}'
    elif (instr & 0xFF800000) == 0xAA000000:
        rm = (instr >> 16) & 0x1F
        rn = (instr >> 5) & 0x1F
        rd = instr & 0x1F
        desc = f'mov x{rd}, x{rn}'
    elif (instr & 0xFFE00000) == 0x34000000:
        imm = (instr >> 5) & 0x7FFF
        if imm & 0x4000:
            imm -= 0x8000
        target = pc + imm * 4
        rt = instr & 0x1F
        desc = f'cbz w{rt}, 0x{target:x}'
    elif (instr & 0xFFE00000) == 0x35000000:
        imm = (instr >> 5) & 0x7FFF
        if imm & 0x4000:
            imm -= 0x8000
        target = pc + imm * 4
        rt = instr & 0x1F
        desc = f'cbnz w{rt}, 0x{target:x}'
    elif (instr & 0xFFE00000) == 0xB4000000:
        imm = (instr >> 5) & 0x7FFF
        if imm & 0x4000:
            imm -= 0x8000
        target = pc + imm * 4
        rt = instr & 0x1F
        desc = f'cbz x{rt}, 0x{target:x}'
    
    marker = ''
    if 'Flashing Unlock' in desc or 'Device already' in desc or 'unlock' in desc.lower() or 'Unlock' in desc:
        marker = ' ★★★'
    elif 'bl 0x' in desc:
        marker = ''
    
    print(f'  0x{pc:x}: {instr:08x}  {desc}{marker}')
    
    if instr == 0xD65F03C0:
        print(f'  --- 函数结束 ---')
        break
