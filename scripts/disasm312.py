"""
Accurate disassembly of Python 3.12 bytecode using opcode module
"""
import marshal
import struct
import zlib
import opcode

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
decrypt_code = code.co_consts[6]

print(f'Python opcode version: {opcode.opmap.get("RESUME", "unknown")}')
print(f'HAVE_ARGUMENT threshold: {opcode.HAVE_ARGUMENT}')
print()

def disasm(code_obj, indent=0):
    bc = code_obj.co_code
    prefix = '  ' * indent
    i = 0
    while i < len(bc):
        op = bc[i]
        arg = bc[i+1] if i+1 < len(bc) else 0
        opname = opcode.opname[op]
        
        # Resolve arg
        arg_repr = ''
        if op >= opcode.HAVE_ARGUMENT:
            if opname == 'LOAD_CONST':
                val = code_obj.co_consts[arg] if arg < len(code_obj.co_consts) else '?'
                if isinstance(val, str):
                    arg_repr = f'({repr(val)})'
                elif isinstance(val, bytes):
                    arg_repr = f'(bytes[{len(val)}])'
                elif isinstance(val, int):
                    arg_repr = f'({val})'
                elif hasattr(val, 'co_name'):
                    arg_repr = f'(code: {val.co_name})'
                else:
                    arg_repr = f'({repr(val)[:40]})'
            elif opname == 'LOAD_FAST' or opname == 'LOAD_FAST_AND_CLEAR' or opname == 'STORE_FAST' or opname == 'DELETE_FAST':
                if arg < len(code_obj.co_varnames):
                    arg_repr = f'({code_obj.co_varnames[arg]})'
            elif opname == 'LOAD_GLOBAL':
                # In 3.12, LOAD_GLOBAL arg has flag in low bit
                name_idx = arg >> 1
                if name_idx < len(code_obj.co_names):
                    arg_repr = f'({code_obj.co_names[name_idx]})'
            elif opname == 'LOAD_ATTR' or opname == 'LOAD_METHOD':
                if arg < len(code_obj.co_names):
                    arg_repr = f'({code_obj.co_names[arg]})'
            elif opname == 'LOAD_NAME':
                if arg < len(code_obj.co_names):
                    arg_repr = f'({code_obj.co_names[arg]})'
            elif opname == 'STORE_NAME':
                if arg < len(code_obj.co_names):
                    arg_repr = f'({code_obj.co_names[arg]})'
            elif opname == 'BINARY_OP':
                # arg is operation type
                ops = {0: '+', 1: '&', 2: '//', 4: '<<', 8: '*', 10: '%', 11: '|', 13: '**', 14: '>>', 16: '-', 17: '/', 19: '//', 20: '@', 21: '^', 22: '|'}
                arg_repr = f'({ops.get(arg, f"op{arg}")})'
            elif 'JUMP' in opname:
                target = i + 2 + arg * 2
                arg_repr = f'(-> {target})'
            else:
                arg_repr = f'(arg={arg})'
        
        if op != 0:  # skip CACHE
            print(f'{prefix}{i:4d}: {op:3d} {opname:25s} {arg_repr}')
        i += 2

print('=== decrypt function ===')
print(f'varnames: {decrypt_code.co_varnames}')
print(f'names: {decrypt_code.co_names}')
print(f'consts: {decrypt_code.co_consts}')
print()
disasm(decrypt_code)

print('\n\n=== Module level (key_table assignment) ===')
disasm(code)
