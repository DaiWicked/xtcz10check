#!/usr/bin/env python3
import struct
import re

data = open('unpacked_abl/author/abl_a_pe32_clean.bin', 'rb').read()

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

print('=== 作者abl中搜索 flashing 相关字符串 ===')
for m in re.finditer(b'flashing[^\x00]*', data):
    s = m.group().decode('ascii', errors='replace')
    print(f'  +0x{m.start():x}: "{s}"')

print()
print('=== 作者abl中搜索 unlock 相关字符串 ===')
for m in re.finditer(b'unlock[^\x00]*', data, re.IGNORECASE):
    s = m.group().decode('ascii', errors='replace')
    if len(s) > 3:
        print(f'  +0x{m.start():x}: "{s}"')

print()
print('=== 作者abl中搜索 "Flashing Unlock is not allowed" ===')
for m in re.finditer(b'Flashing Unlock[^\x00]*', data):
    s = m.group().decode('ascii', errors='replace')
    print(f'  +0x{m.start():x}: "{s}"')

print()
print('=== 作者abl中搜索 "Device already" ===')
for m in re.finditer(b'Device already[^\x00]*', data):
    s = m.group().decode('ascii', errors='replace')
    print(f'  +0x{m.start():x}: "{s}"')

print()
print('=== 作者abl命令表（搜索flashing unlock） ===')
# 搜索命令表
for m in re.finditer(b'flashing unlock\x00', data):
    str_addr = m.start()
    print(f'"flashing unlock" @ 0x{str_addr:x}')
    target_bytes = struct.pack('<I', str_addr)
    pos = data.find(target_bytes)
    if pos != -1:
        func_ptr = struct.unpack_from('<I', data, pos + 8)[0]
        print(f'  命令表 @ 0x{pos:x}, 处理函数 = 0x{func_ptr:x}')

for m in re.finditer(b'flashing lock\x00', data):
    str_addr = m.start()
    print(f'"flashing lock" @ 0x{str_addr:x}')
    target_bytes = struct.pack('<I', str_addr)
    pos = data.find(target_bytes)
    if pos != -1:
        func_ptr = struct.unpack_from('<I', data, pos + 8)[0]
        print(f'  命令表 @ 0x{pos:x}, 处理函数 = 0x{func_ptr:x}')

for m in re.finditer(b'flashing get_unlock_ability\x00', data):
    str_addr = m.start()
    print(f'"flashing get_unlock_ability" @ 0x{str_addr:x}')
    target_bytes = struct.pack('<I', str_addr)
    pos = data.find(target_bytes)
    if pos != -1:
        func_ptr = struct.unpack_from('<I', data, pos + 8)[0]
        print(f'  命令表 @ 0x{pos:x}, 处理函数 = 0x{func_ptr:x}')
