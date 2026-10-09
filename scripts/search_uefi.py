#!/usr/bin/env python3
"""深度搜索 UEFI 镜像中的解锁相关字符串"""
import sys

def search_uefi_image(path):
    with open(path, 'rb') as f:
        data = f.read()
    
    print(f"文件: {path}")
    print(f"大小: {len(data)} bytes")
    
    # 提取所有可打印字符串（长度>=6）
    print("\n=== 所有可打印字符串（长度>=8）===")
    strings = []
    current = b''
    for b in data:
        if 32 <= b < 127:
            current += bytes([b])
        else:
            if len(current) >= 8:
                strings.append(current.decode('ascii', errors='replace'))
            current = b''
    if len(current) >= 8:
        strings.append(current.decode('ascii', errors='replace'))
    
    # 筛选与解锁/分区/安全相关的字符串
    keywords = ['unlock', 'lock', 'flash', 'erase', 'write', 'read', 'partition', 
                'rpmb', 'devinfo', 'frp', 'secure', 'boot', 'verify', 'auth',
                'key', 'cert', 'sign', 'hash', 'state', 'status', 'flag',
                'set', 'get', 'oem', 'fastboot', 'reboot', 'reset', 'format',
                'guid', 'protocol', 'handle', 'locate', 'install',
                'block', 'io', 'storage', 'emmc', 'ufs', 'mmc',
                'log', 'print', 'debug', 'error', 'fail', 'success',
                'init', 'entry', 'main', 'start', 'run', 'exec',
                '小米', 'xiaomi', 'miui', 'hyperos', 'redmi']
    
    print("\n=== 与解锁/分区相关的字符串 ===")
    for s in strings:
        s_lower = s.lower()
        for kw in keywords:
            if kw in s_lower:
                print(f"  {s}")
                break
    
    # 搜索 GUID（UEFI 协议 GUID）
    print("\n=== 可能的 GUID 字符串 ===")
    import re
    guid_pattern = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    for s in strings:
        if re.search(guid_pattern, s):
            print(f"  {s}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法: python search_uefi.py <文件>")
        sys.exit(1)
    search_uefi_image(sys.argv[1])
