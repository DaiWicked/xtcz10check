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

print('=== oem device-info 处理函数 0x32be0 反汇编 ===')
print()

# 从0x32be0开始，打印到下一个函数（遇到ret或下一个函数序言）
func_start = 0x32be0
func_end = func_start + 0x300  # 先打印0x300字节

for pc in range(func_start, func_end, 4):
    instr = struct.unpack_from('<I', data, pc)[0]
    
    # 简单解码
    desc = ''
    if instr == 0xD65F03C0:
        desc = 'ret'
    elif (instr & 0xFFC003FF) == 0xA98003E0:
        desc = 'stp x29,x30,[sp,#-N]!'
    elif (instr & 0xFF8003FF) == 0xD10003FF:
        desc = 'sub sp,sp,#N'
    elif (instr & 0x9F000000) == 0x90000000:
        addr = decode_adrp_add(pc)
        if addr:
            s = read_string(addr)
            if s and len(s) > 2:
                desc = f'adrp+add -> "{s}"'
            else:
                desc = f'adrp+add -> 0x{addr:x}'
    elif (instr & 0xFC000000) == 0x94000000:
        # BL 指令
        imm = instr & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        target = pc + imm * 4
        desc = f'bl 0x{target:x}'
    elif (instr & 0xFF000000) == 0x54000000:
        desc = 'b.cond'
    elif (instr & 0xFC000000) == 0x14000000:
        imm = instr & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        target = pc + imm * 4
        desc = f'b 0x{target:x}'
    
    marker = ''
    if pc == 0x323e0:
        marker = ' <-- IsAllowUnlock打印'
    
    print(f'  0x{pc:x}: {instr:08x}  {desc}{marker}')
    
    # 如果遇到ret，停止
    if instr == 0xD65F03C0:
        print(f'  --- 函数结束 ---')
        break

print()
print('=== 检查 0x32be0 是否调用 0x32300 ===')
# 搜索0x32be0函数范围内的bl 0x32300
for pc in range(0x32be0, 0x32be0 + 0x300, 4):
    instr = struct.unpack_from('<I', data, pc)[0]
    if (instr & 0xFC000000) == 0x94000000:
        imm = instr & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        target = pc + imm * 4
        if 0x32200 <= target <= 0x32400:
            print(f'  0x{pc:x}: bl 0x{target:x}')
