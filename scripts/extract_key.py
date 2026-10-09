"""
Extract full key_table and reconstruct decrypt algorithm
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

# key_table is const index 2
key_table_tuple = code.co_consts[2]
print(f'key_table length: {len(key_table_tuple)}')
print(f'key_table type: {type(key_table_tuple)}')

# Convert to bytes
key_table = bytes(key_table_tuple)
print(f'\n=== Full key_table (256 bytes) ===')
print(f'Hex: {key_table.hex()}')
print(f'\nAs C array:')
for i in range(0, 256, 16):
    line = ', '.join(f'0x{b:02x}' for b in key_table[i:i+16])
    print(f'  {line},')

print(f'\nAs Python bytes:')
print(f'key_table = {repr(key_table)}')

# Also analyze the XtcXorHdrStruct more carefully
print('\n=== XtcXorHdrStruct class analysis ===')
class_code = code.co_consts[3]
print(f'Class co_names: {class_code.co_names}')
print(f'Class co_consts:')
for i, c in enumerate(class_code.co_consts):
    print(f'  [{i}] {type(c).__name__}: {repr(c)[:80]}')

# Analyze decrypt function bytecode manually
print('\n=== decrypt function bytecode analysis ===')
decrypt_code = code.co_consts[6]
print(f'varnames: {decrypt_code.co_varnames}')
print(f'names: {decrypt_code.co_names}')
print(f'consts: {decrypt_code.co_consts}')

# Manual bytecode disassembly for Python 3.12
# Opcode map for common ops
OPCODES = {
    0: 'CACHE', 1: 'POP_TOP', 4: 'END_FOR', 9: 'NOP',
    50: 'BEFORE_WITH', 53: 'RETURN_GENERATOR', 55: 'RETURN_CONST',
    56: 'RETURN_VALUE', 57: 'IMPORT_STAR', 60: 'YIELD_VALUE',
    75: 'SET_FUNCTION_ATTRIBUTE', 83: 'GET_LEN', 84: 'MATCH_MAPPING',
    85: 'MATCH_SEQUENCE', 86: 'MATCH_KEYS', 87: 'COPY_DICT_WITHOUT_KEYS',
    89: 'PUSH_EXC_INFO', 91: 'CHECK_EXC_MATCH', 92: 'CHECK_EG_MATCH',
    95: 'HAVE_ARGUMENT', 100: 'LOAD_CONST', 101: 'LOAD_NAME',
    103: 'BUILD_TUPLE', 104: 'BUILD_LIST', 105: 'BUILD_SET',
    106: 'BUILD_MAP', 107: 'LOAD_ATTR', 108: 'LOAD_SUPER_ATTR',
    110: 'LOAD_GLOBAL', 111: 'LOAD_FAST', 112: 'LOAD_FAST_CHECK',
    113: 'LOAD_FAST_AND_CLEAR', 114: 'STORE_FAST', 115: 'DELETE_FAST',
    116: 'LOAD_FAST_AND_PUSH', 117: 'STORE_FAST_MULTI',
    120: 'STORE_NAME', 121: 'DELETE_NAME', 122: 'UNPACK_SEQUENCE',
    123: 'UNPACK_EX', 124: 'LIST_APPEND', 125: 'SET_ADD',
    126: 'MAP_ADD', 127: 'COPY', 128: 'SWAP', 129: 'CELL_CONTENT',
    130: 'DUP_TOP', 131: 'DUP_TOP_TWO', 132: 'DUP_TOP_THREE',
    133: 'ROT_TWO', 134: 'ROT_THREE', 135: 'ROT_FOUR',
    136: 'ROT_N', 137: 'COPY_FREE_VARS', 140: 'BINARY_OP',
    144: 'LIST_EXTEND', 145: 'SET_UPDATE', 146: 'DICT_MERGE',
    147: 'DICT_UPDATE', 150: 'GET_AITER', 151: 'GET_ANEXT',
    152: 'BEFORE_ASYNC_WITH', 153: 'SEND', 155: 'GET_AWAITABLE',
    156: 'ASYNC_GEN_WRAP', 157: 'MATCH_CLASS', 160: 'LOAD_SUPER_ATTR',
    162: 'SETUP_FINALLY', 163: 'SETUP_CLEANUP', 164: 'SETUP_WITH',
    171: 'POP_EXCEPT', 172: 'RERAISE', 173: 'CHECK_EG_MATCH',
    175: 'JOB', 176: 'JOB', 177: 'JOB', 181: 'JUMP_BACKWARD',
    182: 'JUMP_BACKWARD_NO_INTERRUPT', 183: 'JUMP_FORWARD',
    184: 'JUMP_BACKWARD', 185: 'JUMP_BACKWARD_NO_INTERRUPT',
    186: 'JUMP_FORWARD', 187: 'JUMP_BACKWARD',
    190: 'POP_JUMP_FORWARD_IF_NONE', 191: 'POP_JUMP_BACKWARD_IF_NONE',
    192: 'POP_JUMP_FORWARD_IF_NOT_NONE', 193: 'POP_JUMP_BACKWARD_IF_NOT_NONE',
    194: 'POP_JUMP_FORWARD_IF_TRUE', 195: 'POP_JUMP_BACKWARD_IF_TRUE',
    196: 'POP_JUMP_FORWARD_IF_FALSE', 197: 'POP_JUMP_BACKWARD_IF_FALSE',
    198: 'POP_JUMP_FORWARD_IF_NOT_NONE', 199: 'POP_JUMP_BACKWARD_IF_NOT_NONE',
    200: 'POP_JUMP_FORWARD_IF_NONE', 201: 'POP_JUMP_BACKWARD_IF_NONE',
    202: 'POP_JUMP_FORWARD_IF_TRUE', 203: 'POP_JUMP_BACKWARD_IF_TRUE',
    204: 'POP_JUMP_FORWARD_IF_FALSE', 205: 'POP_JUMP_BACKWARD_IF_FALSE',
    206: 'POP_JUMP_FORWARD_IF_NOT_EQUAL', 207: 'POP_JUMP_BACKWARD_IF_NOT_EQUAL',
    208: 'POP_JUMP_FORWARD_IF_EQUAL', 209: 'POP_JUMP_BACKWARD_IF_EQUAL',
    210: 'POP_JUMP_FORWARD_IF_NOT_EQUAL', 211: 'POP_JUMP_BACKWARD_IF_NOT_EQUAL',
    212: 'POP_JUMP_FORWARD_IF_EQUAL', 213: 'POP_JUMP_BACKWARD_IF_EQUAL',
    214: 'POP_JUMP_FORWARD_IF_TRUE', 215: 'POP_JUMP_BACKWARD_IF_TRUE',
    216: 'POP_JUMP_FORWARD_IF_FALSE', 217: 'POP_JUMP_BACKWARD_IF_FALSE',
    218: 'POP_JUMP_FORWARD_IF_NONE', 219: 'POP_JUMP_BACKWARD_IF_NONE',
    220: 'POP_JUMP_FORWARD_IF_NOT_NONE', 221: 'POP_JUMP_BACKWARD_IF_NOT_NONE',
    222: 'POP_JUMP_FORWARD_IF_EXC_MATCH', 223: 'POP_JUMP_BACKWARD_IF_EXC_MATCH',
    224: 'POP_JUMP_FORWARD_IF_NOT_EXC_MATCH', 225: 'POP_JUMP_BACKWARD_IF_NOT_EXC_MATCH',
    226: 'JUMP_IF_TRUE_OR_POP', 227: 'JUMP_IF_FALSE_OR_POP',
    228: 'JUMP_IF_TRUE_OR_POP', 229: 'JUMP_IF_FALSE_OR_POP',
    230: 'LOAD_GLOBAL', 231: 'LOAD_GLOBAL', 232: 'LOAD_ATTR',
    233: 'LOAD_ATTR', 234: 'LOAD_SUPER_ATTR', 235: 'LOAD_SUPER_ATTR',
    236: 'LOAD_CONST', 237: 'LOAD_CONST', 238: 'LOAD_FAST',
    239: 'LOAD_FAST', 240: 'LOAD_FAST_AND_CLEAR', 241: 'LOAD_FAST_AND_CLEAR',
    242: 'STORE_FAST', 243: 'STORE_FAST', 244: 'DELETE_FAST',
    245: 'DELETE_FAST', 246: 'LOAD_FAST_AND_PUSH', 247: 'LOAD_FAST_AND_PUSH',
    248: 'STORE_FAST_MULTI', 249: 'STORE_FAST_MULTI',
    250: 'LOAD_NAME', 251: 'LOAD_NAME', 252: 'STORE_NAME',
    253: 'STORE_NAME', 254: 'DELETE_NAME', 255: 'DELETE_NAME',
}

# Actually let's just use a simpler approach - print bytecode with opcodes
bc = decrypt_code.co_code
print(f'\nBytecode length: {len(bc)}')
print(f'Bytecode (op, arg) pairs:')
i = 0
while i < len(bc):
    op = bc[i]
    arg = bc[i+1] if i+1 < len(bc) else 0
    opname = OPCODES.get(op, f'OP_{op}')
    print(f'  {i:4d}: {op:3d} {opname:30s} arg={arg:3d} (0x{arg:02x})')
    i += 2
    # Skip CACHE entries
    if op == 0:
        continue
