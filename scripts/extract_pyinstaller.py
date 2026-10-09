"""
PyInstaller extractor - extract pyc files from tool.exe
Based on pyinstxtractor logic
"""
import struct
import sys
import os
import zlib

exe_path = r'D:\gc\MIO-KITCHEN-4.1.8-win\tool.exe'
output_dir = r'H:\xtcz10check\extracted'

os.makedirs(output_dir, exist_ok=True)

with open(exe_path, 'rb') as f:
    data = f.read()

print(f'File size: {len(data)}')

# PyInstaller MAGIC
MAGIC = b'MEI\014\013\012\013\016'

# Find the cookie at the end of file
# PyInstaller stores a CArchive (PKG) with a TOC
# Search for MAGIC
magic_pos = data.rfind(MAGIC)
print(f'MAGIC found at: {magic_pos}')

if magic_pos == -1:
    print('MAGIC not found, trying alternative...')
    # Try to find PKG signature
    for sig in [b'PYZ\x00', b'PYZ\x01', b'cArchive']:
        pos = data.find(sig)
        if pos != -1:
            print(f'Found {sig} at {pos}')
    sys.exit(1)

# Read the CArchive header
# struct: magic(8), length(4), toc_pos(4), toc_len(4), pyver(4), pylib_name(64)
header_size = 8 + 4 + 4 + 4 + 4 + 64
header = data[magic_pos:magic_pos + header_size]
magic, length, toc_pos, toc_len, pyver, pylib_name = struct.unpack('!8sIIII64s', header)
print(f'Archive length: {length}')
print(f'TOC position (relative): {toc_pos}')
print(f'TOC length: {toc_len}')
print(f'Python version: {pyver}')
print(f'Python lib name: {pylib_name.split(b"\\x00")[0]}')

# The CArchive (PKG) starts at file_size - length
# MAGIC is in the cookie at the very end of file
archive_start = len(data) - length
print(f'Archive starts at: {archive_start}')

# TOC is at archive_start + toc_pos
toc_abs = archive_start + toc_pos
print(f'TOC absolute position: {toc_abs}')

# Parse TOC entries
# Each entry: entry_size(4), data_pos(4), data_len(4), uncomp_len(4), is_compressed(1), type_code(1), name(variable)
toc_data = data[toc_abs:toc_abs + toc_len]
pos = 0
entries = []
while pos < len(toc_data):
    if pos + 4 > len(toc_data):
        break
    entry_size = struct.unpack('!I', toc_data[pos:pos+4])[0]
    if entry_size == 0 or pos + entry_size > len(toc_data):
        break
    entry = toc_data[pos:pos+entry_size]
    data_pos = struct.unpack('!I', entry[4:8])[0]
    data_len = struct.unpack('!I', entry[8:12])[0]
    uncomp_len = struct.unpack('!I', entry[12:16])[0]
    is_compressed = entry[16]
    type_code = chr(entry[17])
    name = entry[18:].split(b'\x00')[0].decode('utf-8', errors='replace')
    
    entries.append({
        'name': name,
        'data_pos': data_pos,
        'data_len': data_len,
        'uncomp_len': uncomp_len,
        'compressed': is_compressed,
        'type': type_code
    })
    pos += entry_size

print(f'\nTotal TOC entries: {len(entries)}')
print('\n=== All entries ===')
for e in entries:
    print(f"  [{e['type']}] {e['name']} (pos={e['data_pos']}, len={e['data_len']}, uncomp={e['uncomp_len']}, comp={e['compressed']})")

# Find xtc related entries
print('\n=== XTC related entries ===')
for e in entries:
    if 'xtc' in e['name'].lower() or 'decrypt' in e['name'].lower():
        print(f"  [{e['type']}] {e['name']}")

# Extract all pyc/pyo files
print('\n=== Extracting source files ===')
for e in entries:
    if e['type'] in ('s', 'm', 'M'):  # source module
        abs_pos = archive_start + e['data_pos']
        raw = data[abs_pos:abs_pos + e['data_len']]
        if e['compressed']:
            try:
                raw = zlib.decompress(raw)
            except:
                pass
        
        # Write as .pyc
        safe_name = e['name'].replace('/', '_').replace('\\', '_')
        if not safe_name.endswith('.pyc'):
            safe_name += '.pyc'
        out_path = os.path.join(output_dir, safe_name)
        with open(out_path, 'wb') as f:
            f.write(raw)
        print(f'  Extracted: {safe_name} ({len(raw)} bytes)')

print(f'\nDone. Files extracted to: {output_dir}')
