#!/usr/bin/env python3
import struct

data = open('unpacked_abl/v1.0.1/abl_pe32_clean.bin', 'rb').read()

def decode_adrp_add(pc):
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

print('=== 函数 0x32300-0x32450 引用的字符串 ===')
print()

for pc in range(0x32300, 0x32450, 4):
    addr = decode_adrp_add(pc)
    if addr is not None:
        s = read_string(addr)
        if s and len(s) > 3 and any(c.isalpha() for c in s):
            print(f'  0x{pc:x}: -> 0x{addr:x}: "{s}"')

print()
print('=== 搜索 "oem device-info" 或 "device-info" 字符串 ===')
import re
for m in re.finditer(b'device[ -]?info[^\x00]*', data, re.IGNORECASE):
    print(f'  +0x{m.start():x}: {m.group().decode("ascii", errors="replace")}')

print()
print('=== 搜索 "oem" 命令字符串 ===')
for m in re.finditer(b'oem[^\x00]{0,30}', data):
    s = m.group().decode('ascii', errors='replace')
    if len(s) > 4 and any(c.isalpha() for c in s):
        print(f'  +0x{m.start():x}: "{s}"')
