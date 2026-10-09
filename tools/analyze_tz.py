import struct

with open(r'H:\xtcz10check\decrypted_images\v1.0.1\tz.mbn', 'rb') as f:
    data = f.read()

print(f'文件大小: {len(data)} 字节 ({len(data)/1024/1024:.2f} MB)')

# 搜索 ELF 头
elf_offsets = []
for i in range(len(data) - 4):
    if data[i:i+4] == b'\x7fELF':
        elf_offsets.append(i)
        if len(elf_offsets) <= 10:
            if i + 20 <= len(data):
                ei_class = data[i+4]
                ei_data = data[i+5]
                e_type = struct.unpack_from('<H', data, i+16)[0]
                e_machine = struct.unpack_from('<H', data, i+18)[0]
                if ei_class == 1:
                    e_entry = struct.unpack_from('<I', data, i+24)[0]
                else:
                    e_entry = struct.unpack_from('<Q', data, i+24)[0]
                print(f'  ELF @ 0x{i:08X}: class={ei_class}(1=32bit,2=64bit), data={ei_data}, type={e_type}, machine={e_machine}, entry=0x{e_entry:X}')

print(f'共找到 {len(elf_offsets)} 个 ELF 头')

# 搜索关键字符串
print('\n关键字符串搜索:')
keywords = [b'PAS', b'pil_', b'Unlock', b'auth_and_reset', b'AuthAndReset', b'scm_call', b'SCM', b'peripheral', b'authentication', b'QSEE', b'qsee', b'tz_', b'TZ_']
for kw in keywords:
    count = data.count(kw)
    if count > 0:
        positions = []
        start = 0
        while len(positions) < 3:
            pos = data.find(kw, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
        kw_str = kw.decode('ascii', errors='replace')
        pos_str = str([hex(p) for p in positions])
        print(f'  {kw_str}: {count} 次, 位置: {pos_str}')

# 搜索 MBN 头
print('\nMBN 头分析:')
print(f'  前 32 字节: {data[:32].hex()}')
