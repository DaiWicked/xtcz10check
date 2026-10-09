#!/usr/bin/env python3
"""在 XBL DXE 卷中搜索 imagefv / PIL / MountFv 相关字符串"""
import sys
import os

def search_strings_in_file(filepath, keywords):
    """在文件中搜索关键词，返回 (偏移, 字符串)"""
    with open(filepath, 'rb') as f:
        data = f.read()
    
    results = []
    # 提取所有可打印字符串
    current = b''
    for i, b in enumerate(data):
        if 32 <= b < 127:
            current += bytes([b])
        else:
            if len(current) >= 6:
                s = current.decode('ascii', errors='replace')
                for kw in keywords:
                    if kw.lower() in s.lower():
                        results.append((i - len(current), s))
                        break
            current = b''
    if len(current) >= 6:
        s = current.decode('ascii', errors='replace')
        for kw in keywords:
            if kw.lower() in s.lower():
                results.append((len(data) - len(current), s))
                break
    
    return results

def main():
    inner_fv = r'H:\xtcz10check\unpacked_xbl\v1.0.1\inner_fv.bin'
    
    keywords = [
        'imagefv', 'ImageFv', 'elf_fv', 'elf_single', 'elf_split',
        'pil-', 'PIL', 'MountFv', 'mountfv', 'PartiLabel', 'partilabel',
        'FwName', 'SubsysID', 'PartiGuid', 'FvSimpleFileSystem',
        'LoadImage', 'StartImage', 'MountFvLib', 'ABL.ImageFv',
        'RETAIL', 'imagefv_a', 'imagefv_b'
    ]
    
    print(f"搜索文件: {inner_fv}")
    print(f"文件大小: {os.path.getsize(inner_fv)} bytes")
    print(f"\n关键词: {keywords}")
    print("\n" + "="*80)
    
    results = search_strings_in_file(inner_fv, keywords)
    
    if not results:
        print("未找到匹配的字符串")
        return
    
    print(f"找到 {len(results)} 个匹配:\n")
    for offset, s in results:
        print(f"  0x{offset:08X}: {s}")
    
    # 按模块分组（根据 inner_fv_modules.txt 的偏移范围）
    print("\n" + "="*80)
    print("按模块分组:")
    
    # 读取模块列表
    modules = []
    with open(r'H:\xtcz10check\unpacked_xbl\v1.0.1\inner_fv_modules.txt', 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 4 and '-' in parts[0]:
                range_str = parts[0]
                start_str, end_str = range_str.split('-')
                start = int(start_str, 16)
                end = int(end_str, 16)
                guid = parts[3] if len(parts) > 3 else '?'
                name_char = parts[4] if len(parts) > 4 else '?'
                modules.append((start, end, guid, name_char))
    
    for offset, s in results:
        for start, end, guid, name_char in modules:
            if start <= offset < end:
                print(f"  0x{offset:08X} [模块 0x{start:06X}-0x{end:06X} {guid} {name_char}]: {s}")
                break

if __name__ == '__main__':
    main()
