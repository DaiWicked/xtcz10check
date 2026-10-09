"""
Manually analyze xtc_recovery_helper bytecode
"""
import marshal
import struct
import zlib

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

code = get_code('src.core.xtc_recovery_helper')

print('=== Module level constants ===')
for i, c in enumerate(code.co_consts):
    if isinstance(c, (bytes, bytearray)):
        print(f'  [{i}] BYTES ({len(c)}): {c.hex()}')
        print(f'       as ints: {list(c)}')
    elif isinstance(c, str):
        print(f'  [{i}] STR: {repr(c)}')
    elif isinstance(c, int):
        print(f'  [{i}] INT: {c}')
    elif isinstance(c, float):
        print(f'  [{i}] FLOAT: {c}')
    elif hasattr(c, 'co_consts'):
        print(f'  [{i}] CODE: {c.co_name} (varnames={c.co_varnames})')
    elif isinstance(c, tuple):
        print(f'  [{i}] TUPLE ({len(c)}): {c[:20]}...' if len(c) > 20 else f'  [{i}] TUPLE: {c}')
    else:
        print(f'  [{i}] {type(c).__name__}: {repr(c)[:100]}')

# Find key_table - it's likely a bytes or tuple of ints assigned at module level
print('\n=== Looking for key_table in raw bytecode ===')
bytecode = code.co_code
print(f'Bytecode length: {len(bytecode)}')
print(f'Bytecode hex: {bytecode.hex()}')

# Analyze nested code objects (XtcXorHdrStruct class, decrypt function)
for c in code.co_consts:
    if hasattr(c, 'co_consts'):
        print(f'\n=== Nested: {c.co_name} ===')
        print(f'  co_varnames: {c.co_varnames}')
        print(f'  co_names: {c.co_names}')
        print(f'  co_cellvars: {c.co_cellvars}')
        print(f'  co_freevars: {c.co_freevars}')
        print(f'  Constants:')
        for i, cc in enumerate(c.co_consts):
            if isinstance(cc, (bytes, bytearray)):
                print(f'    [{i}] BYTES ({len(cc)}): {list(cc)}')
            elif isinstance(cc, str):
                print(f'    [{i}] STR: {repr(cc)}')
            elif isinstance(cc, int):
                print(f'    [{i}] INT: {cc}')
            elif hasattr(cc, 'co_consts'):
                print(f'    [{i}] CODE: {cc.co_name}')
            elif isinstance(cc, tuple):
                print(f'    [{i}] TUPLE ({len(cc)}): {list(cc)[:30]}')
            else:
                print(f'    [{i}] {type(cc).__name__}: {repr(cc)[:80]}')
        
        # Print raw bytecode
        print(f'  Bytecode hex: {c.co_code.hex()}')
        
        # Recursively check nested (methods inside class)
        for cc in c.co_consts:
            if hasattr(cc, 'co_consts'):
                print(f'\n  --- Method: {cc.co_name} ---')
                print(f'    varnames: {cc.co_varnames}')
                print(f'    names: {cc.co_names}')
                for j, ccc in enumerate(cc.co_consts):
                    if isinstance(ccc, (bytes, bytearray)):
                        print(f'    [{j}] BYTES ({len(ccc)}): {list(ccc)}')
                    elif isinstance(ccc, str):
                        print(f'    [{j}] STR: {repr(ccc)}')
                    elif isinstance(ccc, int):
                        print(f'    [{j}] INT: {ccc}')
                    elif isinstance(ccc, tuple):
                        print(f'    [{j}] TUPLE ({len(ccc)}): {list(ccc)[:30]}')
                    elif hasattr(ccc, 'co_consts'):
                        print(f'    [{j}] CODE: {ccc.co_name}')
                    else:
                        print(f'    [{j}] {type(ccc).__name__}: {repr(ccc)[:60]}')
