# -*- coding: utf-8 -*-
"""
提取 ButtonsDxe 模块从 inner_fv.bin
DeepSeek 报告位置：0x3196B0
"""
import struct
import os

INNER_FV = r"H:\xtcz10check\unpacked_xbl\v1.0.1\inner_fv.bin"
OUT_DIR = r"H:\xtcz10check\unpacked_xbl\v1.0.1"

def find_pe32_in_range(data, start, max_size=0x20000):
    """在指定范围内搜索 PE32 镜像"""
    end = min(start + max_size, len(data))
    pos = start
    while pos < end - 2:
        if data[pos:pos+2] == b'MZ':
            # 检查 PE 签名
            e_lfanew = struct.unpack_from('<I', data, pos+0x3C)[0]
            if pos + e_lfanew + 4 < len(data) and data[pos+e_lfanew:pos+e_lfanew+4] == b'PE\x00\x00':
                machine = struct.unpack_from('<H', data, pos+e_lfanew+4)[0]
                if machine == 0xAA64:  # AARCH64
                    # 计算实际大小
                    pe_offset = pos + e_lfanew
                    num_sections = struct.unpack_from('<H', data, pe_offset+6)[0]
                    size_opt = struct.unpack_from('<H', data, pe_offset+20)[0]
                    sections_offset = pe_offset + 24 + size_opt
                    max_end = 0
                    for i in range(num_sections):
                        sec = sections_offset + i*40
                        raw_size = struct.unpack_from('<I', data, sec+16)[0]
                        raw_ptr = struct.unpack_from('<I', data, sec+20)[0]
                        max_end = max(max_end, raw_ptr + raw_size)
                    actual_size = max_end - pos
                    return pos, actual_size
        pos += 1
    return None, None

def main():
    with open(INNER_FV, 'rb') as f:
        data = f.read()
    
    print(f"inner_fv.bin 大小: {len(data)} 字节")
    
    # DeepSeek 报告 ButtonsDxe 在 0x3196B0
    # 搜索附近的 PE32
    search_start = 0x310000
    search_end = 0x340000
    
    print(f"\n在 0x{search_start:X} - 0x{search_end:X} 范围内搜索 PE32...")
    
    pe_pos, pe_size = find_pe32_in_range(data, search_start, search_end - search_start)
    
    if pe_pos:
        print(f"\n✅ 找到 PE32 @ 0x{pe_pos:X}, 大小: {pe_size} 字节")
        out_path = os.path.join(OUT_DIR, "ButtonsDxe.pe32")
        with open(out_path, 'wb') as f:
            f.write(data[pe_pos:pe_pos+pe_size])
        print(f"已保存到: {out_path}")
        
        # 打印前几个字节确认
        print(f"前16字节: {data[pe_pos:pe_pos+16].hex()}")
    else:
        print("❌ 未找到 PE32，扩大搜索范围...")
        # 搜索整个文件中包含 "Buttons" 字符串的位置
        for i in range(len(data)-10):
            if b'Buttons' in data[i:i+20]:
                print(f"  找到 'Buttons' 字符串 @ 0x{i:X}: {data[i:i+30]}")
                if i > 100:
                    # 往前搜索 MZ
                    for j in range(max(0, i-0x10000), i):
                        if data[j:j+2] == b'MZ':
                            e_lfanew = struct.unpack_from('<I', data, j+0x3C)[0]
                            if j + e_lfanew + 4 < len(data) and data[j+e_lfanew:j+e_lfanew+4] == b'PE\x00\x00':
                                machine = struct.unpack_from('<H', data, j+e_lfanew+4)[0]
                                if machine == 0xAA64:
                                    print(f"  找到 PE32 @ 0x{j:X}")
                                    break

if __name__ == '__main__':
    main()
