#!/usr/bin/env python3
"""在 kernel 中搜索 cpio 和 init 相关内容"""
import sys

def search_kernel(kernel_path):
    with open(kernel_path, 'rb') as f:
        data = f.read()
    
    print(f"文件大小: {len(data)} bytes")
    
    # 搜索 cpio magic
    print("\n=== 搜索 cpio magic (070701) ===")
    cpio_magic = b'070701'
    positions = []
    start = 0
    while True:
        idx = data.find(cpio_magic, start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + 1
    print(f"找到 {len(positions)} 处")
    for pos in positions[:5]:
        # 读取文件名
        if pos + 110 < len(data):
            namesize = int(data[pos+94:pos+102], 16)
            name_end = pos + 110 + namesize - 1
            if name_end < len(data):
                filename = data[pos+110:name_end].decode('utf-8', errors='replace')
                print(f"  @ 0x{pos:X}: {filename}")
    
    # 搜索可打印字符串
    print("\n=== 搜索关键字符串 ===")
    keywords = [b'/init', b'init.rc', b'ramdisk', b'tmpfs', b'mount', b'busybox', b'toybox', b'fastboot', b'unlock', b'flashing', b'device-info', b'frp', b'partition', b'block', b'shell', b'sh', b'echo', b'cat', b'mkdir', b'exec']
    
    for kw in keywords:
        idx = data.find(kw)
        if idx >= 0:
            # 获取上下文
            start = max(0, idx - 20)
            end = min(len(data), idx + 80)
            context = data[start:end]
            # 转换为可打印字符
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
            print(f"  '{kw.decode()}' @ 0x{idx:X}: {printable}")
    
    # 搜索 gzip 头（可能有内嵌压缩的 cpio）
    print("\n=== 搜索 gzip 头 ===")
    gzip_magic = b'\x1f\x8b'
    gzip_positions = []
    start = 0
    while True:
        idx = data.find(gzip_magic, start)
        if idx == -1:
            break
        gzip_positions.append(idx)
        start = idx + 1
    print(f"找到 {len(gzip_positions)} 处 gzip 头")
    for pos in gzip_positions[:5]:
        print(f"  @ 0x{pos:X}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法: python search_kernel.py <kernel文件>")
        sys.exit(1)
    search_kernel(sys.argv[1])
