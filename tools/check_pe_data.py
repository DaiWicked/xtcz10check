#!/usr/bin/env python3
import struct

data = open('unpacked_abl/author/abl_a_pe32_clean.bin', 'rb').read()

print('=== PE头分析 ===')
# MZ头
print(f'MZ签名: {data[0:2]}')
pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
print(f'PE头偏移: 0x{pe_offset:x}')
print(f'PE签名: {data[pe_offset:pe_offset+4]}')

# COFF头
machine = struct.unpack_from('<H', data, pe_offset+4)[0]
num_sections = struct.unpack_from('<H', data, pe_offset+6)[0]
print(f'机器类型: 0x{machine:x}')
print(f'段数量: {num_sections}')

# 可选头
opt_header_offset = pe_offset + 24
magic = struct.unpack_from('<H', data, opt_header_offset)[0]
print(f'可选头magic: 0x{magic:x}')

if magic == 0x20b:  # PE32+
    image_base = struct.unpack_from('<Q', data, opt_header_offset + 24)[0]
    size_of_headers = struct.unpack_from('<I', data, opt_header_offset + 60)[0]
    print(f'ImageBase: 0x{image_base:x}')
    print(f'SizeOfHeaders: 0x{size_of_headers:x}')
    
    # 段表
    section_table_offset = opt_header_offset + 112 + (16 * 4)  # 数据目录之后
    print()
    print('=== 段表 ===')
    for i in range(num_sections):
        offset = section_table_offset + i * 40
        name = data[offset:offset+8].rstrip(b'\x00').decode('ascii', errors='replace')
        virtual_size = struct.unpack_from('<I', data, offset+8)[0]
        virtual_address = struct.unpack_from('<I', data, offset+12)[0]
        raw_size = struct.unpack_from('<I', data, offset+16)[0]
        raw_offset = struct.unpack_from('<I', data, offset+20)[0]
        print(f'  {name:8s} VA=0x{virtual_address:08x} VS=0x{virtual_size:08x} '
              f'RawPtr=0x{raw_offset:08x} RawSize=0x{raw_size:08x}')
        
        # 检查0x7539C是否在这个段内
        target_rva = 0x7539C  # 假设这是RVA（相对虚拟地址）
        if virtual_address <= target_rva < virtual_address + virtual_size:
            file_offset = raw_offset + (target_rva - virtual_address)
            print(f'    ★ 0x7539C 在此段内！文件偏移 = 0x{file_offset:x}')
            if file_offset < len(data):
                val = struct.unpack_from('<I', data, file_offset)[0]
                print(f'    ★ 初始值 = 0x{val:08x} ({val})')

print()
print('=== 检查 0x75390 附近的内存（假设是RVA） ===')
# 尝试将0x75390作为RVA，找到对应的文件偏移
target_rva = 0x75390
for i in range(num_sections):
    offset = section_table_offset + i * 40
    name = data[offset:offset+8].rstrip(b'\x00').decode('ascii', errors='replace')
    virtual_size = struct.unpack_from('<I', data, offset+8)[0]
    virtual_address = struct.unpack_from('<I', data, offset+12)[0]
    raw_size = struct.unpack_from('<I', data, offset+16)[0]
    raw_offset = struct.unpack_from('<I', data, offset+20)[0]
    
    if virtual_address <= target_rva < virtual_address + max(virtual_size, raw_size):
        file_offset = raw_offset + (target_rva - virtual_address)
        print(f'0x75390 在段 {name} 内，文件偏移 = 0x{file_offset:x}')
        if file_offset < len(data) - 64:
            print('前64字节:')
            for j in range(0, 64, 16):
                hex_str = ' '.join(f'{data[file_offset+j+k]:02x}' for k in range(16))
                print(f'  +{j:02x}: {hex_str}')
