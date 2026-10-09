#!/usr/bin/env python3
import struct
import re

data = open('unpacked_abl/author/abl_a_pe32_clean.bin', 'rb').read()

print('=== 搜索确认界面相关字符串 ===')
keywords = [b'lock the bootloader', b'warming', b'confirm', b'press', b'power', b'volume', b'continue', b'cancel']
for kw in keywords:
    for m in re.finditer(kw + b'[^\x00]*', data, re.IGNORECASE):
        s = m.group().decode('ascii', errors='replace')
        if len(s) > 3:
            print(f'  +0x{m.start():x}: "{s[:80]}"')

print()
print('=== 搜索 "Lock the bootloader" 附近的字符串 ===')
for m in re.finditer(b'[Ll]ock[^\x00]{0,50}', data):
    s = m.group().decode('ascii', errors='replace')
    if len(s) > 5:
        print(f'  +0x{m.start():x}: "{s}"')

print()
print('=== 搜索 fastboot oem 命令（作者abl） ===')
for m in re.finditer(b'oem [^\x00]{2,40}', data):
    s = m.group().decode('ascii', errors='replace')
    print(f'  +0x{m.start():x}: "{s}"')

print()
print('=== 搜索 "set_unlock" 或 "lock_state" 相关 ===')
for m in re.finditer(b'[unlock_]*lock[^\x00]{0,30}', data, re.IGNORECASE):
    s = m.group().decode('ascii', errors='replace')
    if len(s) > 4 and ('state' in s.lower() or 'set' in s.lower() or 'flag' in s.lower()):
        print(f'  +0x{m.start():x}: "{s}"')
