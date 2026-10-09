"""
Extract PYZ.pyz - list TOC format
"""
import struct
import zlib
import os
import marshal

exe_path = r'D:\gc\MIO-KITCHEN-4.1.8-win\tool.exe'
output_dir = r'H:\xtcz10check\pyz_extracted'
os.makedirs(output_dir, exist_ok=True)

with open(exe_path, 'rb') as f:
    data = f.read()

archive_start = 429568
pyz_abs = archive_start + 19269501
pyz_data = data[pyz_abs:pyz_abs + 8456232]

toc_offset = struct.unpack('!I', pyz_data[8:12])[0]
toc_data = pyz_data[toc_offset:]
toc = marshal.loads(toc_data)

print(f'TOC type: {type(toc)}, length: {len(toc)}')
print(f'First 3 entries: {toc[:3]}')

# TOC is list of (name, (is_pkg, offset, length)) or similar
# Let's inspect structure
if toc and isinstance(toc[0], tuple):
    print(f'Entry[0] type: {type(toc[0])}, len: {len(toc[0])}')
    print(f'Entry[0]: {toc[0]}')
    if isinstance(toc[0][1], tuple):
        print(f'Entry[0][1]: {toc[0][1]}')

# Build dict
toc_dict = {}
for entry in toc:
    if isinstance(entry, tuple) and len(entry) >= 2:
        name = entry[0]
        info = entry[1]
        if isinstance(info, tuple) and len(info) >= 3:
            toc_dict[name] = info  # (is_pkg, offset, length)

print(f'\nParsed modules: {len(toc_dict)}')

# Find xtc/decrypt modules
print('\n=== XTC/decrypt related modules ===')
for name in sorted(toc_dict.keys()):
    if 'xtc' in name.lower() or 'decrypt' in name.lower() or 'recovery' in name.lower():
        print(f'  {name}: {toc_dict[name]}')

# List src.core modules
print('\n=== src.core modules ===')
for name in sorted(toc_dict.keys()):
    if name.startswith('src.core'):
        print(f'  {name}')

# Extract all modules
print('\n=== Extracting modules ===')
extracted = 0
for name, info in toc_dict.items():
    try:
        is_pkg, offset, length = info[0], info[1], info[2]
        raw = pyz_data[offset:offset + length]
        try:
            code_data = zlib.decompress(raw)
        except:
            code_data = raw
        
        safe_name = name.replace('.', '_').replace('/', '_')
        out_path = os.path.join(output_dir, safe_name + '.pyc')
        with open(out_path, 'wb') as f:
            f.write(b'\xa7\x0d\x0d\x0a')  # Python 3.12 magic
            f.write(b'\x00' * 4)
            f.write(b'\x00' * 8)
            f.write(code_data)
        extracted += 1
    except Exception as e:
        pass

print(f'Extracted {extracted} modules to {output_dir}')

# Specifically extract and dump xtc_recovery_helper
xtc_name = 'src.core.xtc_recovery_helper'
if xtc_name in toc_dict:
    info = toc_dict[xtc_name]
    is_pkg, offset, length = info
    raw = pyz_data[offset:offset + length]
    code_data = zlib.decompress(raw)
    xtc_path = os.path.join(output_dir, 'xtc_recovery_helper.pyc')
    with open(xtc_path, 'wb') as f:
        f.write(b'\xa7\x0d\x0d\x0a')
        f.write(b'\x00' * 4)
        f.write(b'\x00' * 8)
        f.write(code_data)
    print(f'\nXTC module extracted: {xtc_path} ({len(code_data)} bytes code)')
    
    # Try to disassemble
    import dis
    code_obj = marshal.loads(code_data)
    print(f'Code object: {code_obj}')
    print(f'Co names: {code_obj.co_names}')
    print(f'Co consts (strings): {[c for c in code_obj.co_consts if isinstance(c, str)]}')
