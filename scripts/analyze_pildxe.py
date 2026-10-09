#!/usr/bin/env python3
"""提取 PILDxe 模块并分析关键逻辑"""
import os
import struct

def extract_pildxe():
    inner_fv = r'H:\xtcz10check\unpacked_xbl\v1.0.1\inner_fv.bin'
    output_dir = r'H:\xtcz10check\unpacked_xbl\v1.0.1'
    
    with open(inner_fv, 'rb') as f:
        data = f.read()
    
    # PILDxe 模块范围: 0x42AD18 - 0x445D60 (从模块列表)
    # 但实际 PE32 可能有 FFS 头，需要找到 PE 头
    start = 0x42AD18
    end = 0x445D60
    
    print(f"PILDxe 模块范围: 0x{start:X} - 0x{end:X}")
    print(f"模块大小: {end - start} bytes")
    
    # 搜索 PE 头 (MZ)
    pe_offset = None
    for i in range(start, min(start + 0x1000, end)):
        if data[i:i+2] == b'MZ':
            pe_offset = i
            print(f"找到 MZ 头 @ 0x{i:X}")
            break
    
    if pe_offset:
        # 提取 PE32 模块
        pildxe_data = data[pe_offset:end]
        output_path = os.path.join(output_dir, 'PILDxe.pe32')
        with open(output_path, 'wb') as f:
            f.write(pildxe_data)
        print(f"已提取 PILDxe.pe32: {len(pildxe_data)} bytes")
        
        # 分析 PE 头
        if len(pildxe_data) > 0x40:
            e_lfanew = struct.unpack_from('<I', pildxe_data, 0x3C)[0]
            print(f"PE 头偏移: 0x{e_lfanew:X}")
            if pildxe_data[e_lfanew:e_lfanew+4] == b'PE\x00\x00':
                print("PE 签名验证通过")
                machine = struct.unpack_from('<H', pildxe_data, e_lfanew+4)[0]
                print(f"机器类型: 0x{machine:X} (0xAA64=ARM64)")
    
    return pe_offset

def analyze_pildxe_strings():
    """分析 PILDxe 模块中的关键字符串和代码逻辑"""
    inner_fv = r'H:\xtcz10check\unpacked_xbl\v1.0.1\inner_fv.bin'
    
    with open(inner_fv, 'rb') as f:
        data = f.read()
    
    start = 0x42AD18
    end = 0x445D60
    module_data = data[start:end]
    
    print("\n" + "="*80)
    print("PILDxe 模块关键字符串分析")
    print("="*80)
    
    # 提取所有可打印字符串
    strings = []
    current = b''
    for i, b in enumerate(module_data):
        if 32 <= b < 127:
            current += bytes([b])
        else:
            if len(current) >= 8:
                strings.append((start + i - len(current), current.decode('ascii', errors='replace')))
            current = b''
    if len(current) >= 8:
        strings.append((start + len(module_data) - len(current), current.decode('ascii', errors='replace')))
    
    # 分类关键字符串
    categories = {
        'RETAIL/白名单': ['retail', 'RETAIL', 'whitelist', 'allow', 'support'],
        '认证/验签': ['auth', 'Auth', 'PAS', 'sign', 'Sign', 'verify', 'Verify', 'validate', 'Validate', 'metadata', 'hash', 'Hash'],
        '加载/装载': ['load', 'Load', 'mount', 'Mount', 'partition', 'Partition', 'ELF', 'elf', 'segment', 'Segment'],
        '错误/状态': ['fail', 'Fail', 'error', 'Error', 'success', 'Success', 'status', 'Status', 'return', 'Return'],
        'ImageFv相关': ['ImageFv', 'imagefv', 'elf_fv', 'FwName', 'SubsysID', 'PartiLabel', 'PartiGuid'],
    }
    
    for cat, keywords in categories.items():
        print(f"\n--- {cat} ---")
        for offset, s in strings:
            for kw in keywords:
                if kw in s:
                    print(f"  0x{offset:X}: {s}")
                    break
    
    return strings

if __name__ == '__main__':
    extract_pildxe()
    analyze_pildxe_strings()
