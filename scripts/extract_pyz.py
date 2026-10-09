"""
Extract PYZ.pyz archive and find xtc related modules
"""
import struct
import zlib
import os
import sys

pyz_path = r'H:\xtcz10check\extracted\PYZ.pyz'
output_dir = r'H:\xtcz10check\pyz_extracted'

# First extract PYZ from the exe
exe_path = r'D:\gc\MIO-KITCHEN-4.1.8-win\tool.exe'
with open(exe_path, 'rb') as f:
    data = f.read()

# Find PYZ entry - we know from TOC it's at pos 19269501 relative to archive_start
# archive_start = 429568
archive_start = 429568
pyz_abs = archive_start + 19269501
pyz_data = data[pyz_abs:pyz_abs + 8456232]

os.makedirs(output_dir, exist_ok=True)
with open(pyz_path, 'wb') as f:
    f.write(pyz_data)
print(f'PYZ extracted: {len(pyz_data)} bytes')

# Parse PYZ format
# PYZ magic: PYZ\x00
magic = pyz_data[:4]
print(f'PYZ magic: {magic}')

# PYZ structure: magic(4), python_version(4), TOC_offset(4)
# Then TOC is a marshalled dict
pymagic = pyz_data[4:8]
toc_offset = struct.unpack('!I', pyz_data[8:12])[0]
print(f'Python magic: {pymagic.hex()}')
print(f'TOC offset: {toc_offset}')

# TOC is a zlib compressed marshalled dict? Actually it's just marshal
# Let's try to read the TOC
toc_data = pyz_data[toc_offset:]
print(f'TOC data size: {len(toc_data)}')

# Try to unmarshal
import marshal
try:
    toc = marshal.loads(toc_data)
    print(f'TOC type: {type(toc)}')
    if isinstance(toc, dict):
        print(f'TOC entries: {len(toc)}')
        # Find xtc modules
        xtc_modules = {k: v for k, v in toc.items() if 'xtc' in k.lower() or 'decrypt' in k.lower()}
        print(f'\nXTC/decrypt modules in PYZ:')
        for k, v in xtc_modules.items():
            print(f'  {k}: {v}')
        
        # Also list all src.core modules
        core_modules = {k: v for k, v in toc.items() if k.startswith('src.core')}
        print(f'\nsrc.core modules ({len(core_modules)}):')
        for k in sorted(core_modules.keys()):
            print(f'  {k}')
except Exception as e:
    print(f'Marshal error: {e}')
    # Try zlib decompress first
    try:
        toc_decomp = zlib.decompress(toc_data)
        toc = marshal.loads(toc_decomp)
        print(f'Decompressed TOC entries: {len(toc)}')
    except Exception as e2:
        print(f'Decompress error: {e2}')

# Extract all modules from PYZ
# Each entry in TOC: (is_pkg, offset, length) 
# The actual code object is at pyz_data[offset:offset+length], zlib compressed
if isinstance(toc, dict):
    print('\n=== Extracting all modules ===')
    for name, entry in toc.items():
        try:
            if isinstance(entry, tuple):
                is_pkg, offset, length = entry[0], entry[1], entry[2]
            else:
                continue
            
            raw = pyz_data[offset:offset + length]
            try:
                code_data = zlib.decompress(raw)
            except:
                code_data = raw
            
            # Write as .pyc
            safe_name = name.replace('.', '_').replace('/', '_')
            out_path = os.path.join(output_dir, safe_name + '.pyc')
            with open(out_path, 'wb') as f:
                # Add pyc header for Python 3.12
                f.write(b'\xa7\x0d\x0d\x0a')  # magic for 3.12
                f.write(b'\x00' * 4)  # flags
                f.write(b'\x00' * 8)  # timestamp + size
                f.write(code_data)
        except Exception as e:
            pass
    
    print(f'Extracted {len(toc)} modules to {output_dir}')
