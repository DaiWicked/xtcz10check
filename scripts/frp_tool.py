#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FRP 分区分析与授权位修改工具
用于小天才 Z10 (ND03) Bootloader 解锁研究

用法:
  python frp_tool.py analyze <frp.img>          # 分析 FRP 分区内容
  python frp_tool.py set <input.img> <output.img> <offset> <value>  # 设置授权位
  python frp_tool.py dump <frp.img> [offset] [length]  # 十六进制 dump
"""

import sys
import struct
import os

FRP_SIZE = 512 * 1024  # 512 KB = 1024 扇区

def analyze_frp(filepath):
    """分析 FRP 分区内容，寻找 IsAllowUnlock 候选偏移"""
    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"=== FRP 分区分析 ===")
    print(f"文件: {filepath}")
    print(f"大小: {len(data)} 字节 ({len(data)//512} 扇区)")
    print()

    # 检查是否全零
    if all(b == 0 for b in data):
        print("⚠️  FRP 分区全零！")
        print("   这意味着设备从未设置过 FRP 数据（包括 IsAllowUnlock）")
        print("   候选偏移 +0x08 的值为 0（不允许解锁）")
        print()
        print("建议：直接在 +0x08 写入 1，然后测试 oem device-info 是否变为 IsAllowUnlock is 1")
        return

    # 打印前 256 字节
    print("--- 前 256 字节 (十六进制) ---")
    for i in range(0, min(256, len(data)), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        print(f"{i:08x}: {hex_part:<48} {ascii_part}")
    print()

    # 寻找非零 u32 值
    print("--- 非零 u32 值（候选授权位）---")
    nonzero_count = 0
    for i in range(0, min(4096, len(data)), 4):
        val = struct.unpack_from('<I', data, i)[0]
        if val != 0:
            nonzero_count += 1
            if nonzero_count <= 30:
                # 尝试解释
                interpretation = ""
                if val == 1:
                    interpretation = "← 可能是布尔标志（如 IsAllowUnlock=1）"
                elif val == 0xFFFFFFFF:
                    interpretation = "← 可能是未初始化/擦除状态"
                print(f"  +0x{i:04x}: 0x{val:08x} ({val}) {interpretation}")
    if nonzero_count > 30:
        print(f"  ... 还有 {nonzero_count - 30} 个非零值")
    if nonzero_count == 0:
        print("  （前 4KB 内无非零值）")
    print()

    # 检查候选偏移 +0x08
    if len(data) >= 12:
        val_at_08 = struct.unpack_from('<I', data, 0x08)[0]
        print(f"--- 候选偏移 +0x08 (DeepSeek 推测的 IsAllowUnlock) ---")
        print(f"  当前值: 0x{val_at_08:08x} ({val_at_08})")
        if val_at_08 == 0:
            print(f"  → 0 = 不允许解锁（需要改为 1）")
        elif val_at_08 == 1:
            print(f"  → 1 = 允许解锁！可以直接进入下一步")
        else:
            print(f"  → 非 0/1 值，需要进一步分析")
    print()

    # 寻找字符串
    print("--- 可打印字符串（前 4KB）---")
    current = ""
    strings = []
    for i in range(min(4096, len(data))):
        b = data[i]
        if 32 <= b < 127:
            current += chr(b)
        else:
            if len(current) >= 4:
                strings.append((i - len(current), current))
            current = ""
    if len(current) >= 4:
        strings.append((len(data) - len(current), current))

    if strings:
        for offset, s in strings[:20]:
            print(f"  +0x{offset:04x}: \"{s}\"")
    else:
        print("  （无）")
    print()

    # 检查 FRP 头签名（如果有）
    print("--- 头签名检查 ---")
    if len(data) >= 4:
        magic = data[:4]
        print(f"  前 4 字节: {magic.hex()} = '{''.join(chr(b) if 32<=b<127 else '.' for b in magic)}'")
    print()

def set_frp_value(input_path, output_path, offset, value):
    """设置 FRP 分区指定偏移的值"""
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())

    offset = int(offset, 0) if isinstance(offset, str) else offset
    value = int(value, 0) if isinstance(value, str) else value

    if offset + 4 > len(data):
        print(f"错误：偏移 0x{offset:x} 超出文件大小 {len(data)}")
        sys.exit(1)

    old_val = struct.unpack_from('<I', data, offset)[0]
    struct.pack_into('<I', data, offset, value)

    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"=== FRP 修改完成 ===")
    print(f"输入: {input_path}")
    print(f"输出: {output_path}")
    print(f"偏移: +0x{offset:04x}")
    print(f"旧值: 0x{old_val:08x} ({old_val})")
    print(f"新值: 0x{value:08x} ({value})")
    print(f"文件大小: {len(data)} 字节 (必须 524288 = 512KB)")

    if len(data) != FRP_SIZE:
        print(f"⚠️  警告：文件大小 {len(data)} != 预期 {FRP_SIZE}")
        print("   可能需要用 dd 补齐到 512KB 再写入分区")

def dump_frp(filepath, offset=0, length=256):
    """十六进制 dump FRP 分区"""
    with open(filepath, 'rb') as f:
        data = f.read()

    offset = int(offset, 0) if isinstance(offset, str) else offset
    length = int(length, 0) if isinstance(length, str) else length

    print(f"=== FRP dump: +0x{offset:x}, 长度 {length} ===")
    for i in range(offset, min(offset + length, len(data)), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        print(f"{i:08x}: {hex_part:<48} {ascii_part}")

def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'analyze':
        analyze_frp(sys.argv[2])
    elif cmd == 'set':
        if len(sys.argv) < 6:
            print("用法: python frp_tool.py set <input.img> <output.img> <offset> <value>")
            sys.exit(1)
        set_frp_value(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    elif cmd == 'dump':
        offset = sys.argv[3] if len(sys.argv) > 3 else 0
        length = sys.argv[4] if len(sys.argv) > 4 else 256
        dump_frp(sys.argv[2], offset, length)
    else:
        print(f"未知命令: {cmd}")
        print(__doc__)
        sys.exit(1)

if __name__ == '__main__':
    main()
