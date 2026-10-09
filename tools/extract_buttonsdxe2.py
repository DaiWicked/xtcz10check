# -*- coding: utf-8 -*-
"""
可靠提取 ButtonsDxe 模块
"""
import struct
import os

INNER_FV = r"H:\xtcz10check\unpacked_xbl\v1.0.1\inner_fv.bin"
OUT_DIR = r"H:\xtcz10check\unpacked_xbl\v1.0.1"

def main():
    with open(INNER_FV, 'rb') as f:
        data = f.read()
    
    print(f"inner_fv.bin 大小: {len(data)} 字节")
    
    # 搜索所有 AARCH64 PE32
    pe_list = []
    pos = 0
    while pos < len(data) - 2:
        if data[pos:pos+2] == b'MZ':
            try:
                e_lfanew = struct.unpack_from('<I', data, pos+0x3C)[0]
                if pos + e_lfanew + 24 < len(data) and data[pos+e_lfanew:pos+e_lfanew+4] == b'PE\x00\x00':
                    machine = struct.unpack_from('<H', data, pos+e_lfanew+4)[0]
                    if machine == 0xAA64:
                        # 用节表计算大小
                        pe_offset = pos + e_lfanew
                        num_sections = struct.unpack_from('<H', data, pe_offset+6)[0]
                        size_opt = struct.unpack_from('<H', data, pe_offset+20)[0]
                        sections_offset = pe_offset + 24 + size_opt
                        max_end = pos + 0x200  # 最小大小
                        for i in range(num_sections):
                            sec = sections_offset + i*40
                            raw_size = struct.unpack_from('<I', data, sec+16)[0]
                            raw_ptr = struct.unpack_from('<I', data, sec+20)[0]
                            if raw_ptr > 0 and raw_size > 0:
                                max_end = max(max_end, pos + raw_ptr + raw_size)
                        actual_size = max_end - pos
                        if actual_size > 0 and actual_size < 0x100000:  # 合理范围
                            pe_list.append((pos, actual_size))
                            print(f"  PE32 @ 0x{pos:X}, size={actual_size}, sections={num_sections}")
            except:
                pass
        pos += 1
    
    print(f"\n共找到 {len(pe_list)} 个 AARCH64 PE32")
    
    # 找到包含 "Buttons" 字符串的 PE32
    for pe_pos, pe_size in pe_list:
        pe_data = data[pe_pos:pe_pos+pe_size]
        if b'Buttons' in pe_data or b'buttons' in pe_data or b'BUTTONS' in pe_data:
            print(f"\n✅ 找到 ButtonsDxe @ 0x{pe_pos:X}, size={pe_size}")
            out_path = os.path.join(OUT_DIR, "ButtonsDxe.pe32")
            with open(out_path, 'wb') as f:
                f.write(pe_data)
            print(f"已保存到: {out_path}")
            
            # 搜索相关字符串
            for keyword in [b'ButtonsInit', b'InitializeKeyMap', b'PollPowerKey', b'PollButtonArray', 
                           b'Power Button', b'VOL+', b'VOL-', b'PmicGpio', b'PmicPON',
                           b'ButtonsLib', b'ConfigureButton', b'KeyMap']:
                idx = pe_data.find(keyword)
                if idx >= 0:
                    # 提取周围的字符串
                    start = max(0, idx-10)
                    end = min(len(pe_data), idx+60)
                    s = pe_data[start:end]
                    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in s)
                    print(f"  字符串 '{keyword.decode()}' @ 0x{idx:X}: ...{printable}...")
            return
    
    print("\n❌ 未找到包含 'Buttons' 的 PE32")
    # 列出所有 PE32 的位置，帮助定位
    print("\n所有 PE32 位置:")
    for pe_pos, pe_size in pe_list:
        pe_data = data[pe_pos:pe_pos+pe_size]
        # 找第一个可打印字符串
        for i in range(0, min(len(pe_data), 0x2000)):
            if pe_data[i:i+5] == b'Buttons' or pe_data[i:i+3] == b'Ebl' or pe_data[i:i+5] == b'QcomB':
                print(f"  0x{pe_pos:X}: 包含 '{pe_data[i:i+10]}'")
                break

if __name__ == '__main__':
    main()
