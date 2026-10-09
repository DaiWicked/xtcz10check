"""
Disassemble xtc_recovery_helper and ofp_qc_decrypt
"""
import marshal
import dis
import struct
import zlib
import os

exe_path = r'D:\gc\MIO-KITCHEN-4.1.8-win\tool.exe'
with open(exe_path, 'rb') as f:
    data = f.read()

archive_start = 429568
pyz_abs = archive_start + 19269501
pyz_data = data[pyz_abs:pyz_abs + 8456232]

toc_offset = struct.unpack('!I', pyz_data[8:12])[0]
toc_data = pyz_data[toc_offset:]
toc = marshal.loads(toc_data)
toc_dict = {entry[0]: entry[1] for entry in toc}

def get_code(name):
    info = toc_dict[name]
    is_pkg, offset, length = info
    raw = pyz_data[offset:offset + length]
    code_data = zlib.decompress(raw)
    return marshal.loads(code_data)

def dump_consts(code_obj, indent=0):
    """Recursively dump all string/bytes constants"""
    prefix = '  ' * indent
    for c in code_obj.co_consts:
        if isinstance(c, str) and len(c) > 0:
            print(f'{prefix}STR: {repr(c)}')
        elif isinstance(c, (bytes, bytearray)):
            print(f'{prefix}BYTES: {repr(c[:100])}')
        elif hasattr(c, 'co_consts'):
            print(f'{prefix}CODE: {c.co_name} (names={c.co_names})')
            dump_consts(c, indent + 1)

# === xtc_recovery_helper ===
print('=' * 70)
print('src.core.xtc_recovery_helper')
print('=' * 70)
code = get_code('src.core.xtc_recovery_helper')
print(f'\nModule names: {code.co_names}')
print(f'\n--- All constants ---')
dump_consts(code)

print(f'\n--- Full disassembly ---')
dis.dis(code)

# Also disassemble nested functions
for c in code.co_consts:
    if hasattr(c, 'co_consts') and c.co_name != '<module>':
        print(f'\n\n=== Function: {c.co_name} ===')
        print(f'Names: {c.co_names}')
        print(f'Varnames: {c.co_varnames}')
        dis.dis(c)

# === ofp_qc_decrypt ===
print('\n\n' + '=' * 70)
print('src.core.ofp_qc_decrypt')
print('=' * 70)
code2 = get_code('src.core.ofp_qc_decrypt')
print(f'\nModule names: {code2.co_names}')
print(f'\n--- All constants ---')
dump_consts(code2)
print(f'\n--- Full disassembly ---')
dis.dis(code2)
for c in code2.co_consts:
    if hasattr(c, 'co_consts') and c.co_name != '<module>':
        print(f'\n\n=== Function: {c.co_name} ===')
        print(f'Names: {c.co_names}')
        print(f'Varnames: {c.co_varnames}')
        dis.dis(c)
