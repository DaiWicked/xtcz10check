#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
misc 分区 BCB (Bootloader Control Block) 生成工具
用于小天才 Z10 (ND03) 控制启动模式

用法:
  python make_misc_bcb.py boot-fastboot <output.img> --from <backup.img>
  python make_misc_bcb.py boot-normal <output.img> --from <backup.img>
  python make_misc_bcb.py analyze <misc.img>

BCB 命令（已知）:
  boot-fastboot  - 进入 fastboot 模式
  boot-recovery  - 进入 recovery 模式
  ffbm-02        - 工厂模式 (QMMI)
"""

import sys
import struct
import os

MISC_SIZE = 1024 * 1024  # 1 MB = 2048 扇区
BCB_COMMAND_OFFSET = 0
BCB_COMMAND_SIZE = 32  # 命令字段大小（推测）

KNOWN_COMMANDS = [
    'boot-fastboot',
    'boot-recovery',
    'ffbm-02',
    'boot-normal',
]

def make_bcb(command, output_path, backup_path=None):
    """生成 BCB 镜像"""
    if backup_path and os.path.exists(backup_path):
        with open(backup_path, 'rb') as f:
            data = bytearray(f.read())
        print(f"基于备份: {backup_path} ({len(data)} 字节)")
    else:
        data = bytearray(MISC_SIZE)
        print(f"创建新镜像: {MISC_SIZE} 字节")

    # 确保大小正确
    if len(data) < MISC_SIZE:
        data.extend(b'\x00' * (MISC_SIZE - len(data)))
    elif len(data) > MISC_SIZE:
        data = data[:MISC_SIZE]

    # 写入命令（先清零命令区域，再写入）
    cmd_bytes = command.encode('ascii') + b'\x00'
    for i in range(BCB_COMMAND_SIZE):
        data[BCB_COMMAND_OFFSET + i] = 0
    for i, b in enumerate(cmd_bytes):
        if i < BCB_COMMAND_SIZE:
            data[BCB_COMMAND_OFFSET + i] = b

    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"=== BCB 生成完成 ===")
    print(f"输出: {output_path}")
    print(f"命令: '{command}'")
    print(f"大小: {len(data)} 字节")
    print(f"前 32 字节: {data[:32].hex()}")
    print(f"前 16 字节 ASCII: '{''.join(chr(b) if 32<=b<127 else '.' for b in data[:16])}'")

def analyze_misc(filepath):
    """分析 misc 分区内容"""
    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"=== misc 分区分析 ===")
    print(f"文件: {filepath}")
    print(f"大小: {len(data)} 字节 ({len(data)//512} 扇区)")
    print()

    # 读取 BCB 命令
    cmd = data[BCB_COMMAND_OFFSET:BCB_COMMAND_OFFSET + BCB_COMMAND_SIZE]
    cmd_str = cmd.split(b'\x00')[0].decode('ascii', errors='replace')
    print(f"BCB 命令 (偏移 0x{BCB_COMMAND_OFFSET:x}): '{cmd_str}'")

    if cmd_str in KNOWN_COMMANDS:
        print(f"  → 已知命令")
    else:
        print(f"  → 未知命令")
    print()

    # 打印前 256 字节
    print("--- 前 256 字节 ---")
    for i in range(0, min(256, len(data)), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        print(f"{i:08x}: {hex_part:<48} {ascii_part}")
    print()

    # 寻找非零区域
    print("--- 非零区域 ---")
    nonzero_regions = []
    in_nonzero = False
    start = 0
    for i in range(len(data)):
        if data[i] != 0:
            if not in_nonzero:
                start = i
                in_nonzero = True
        else:
            if in_nonzero:
                nonzero_regions.append((start, i - start))
                in_nonzero = False
    if in_nonzero:
        nonzero_regions.append((start, len(data) - start))

    for offset, length in nonzero_regions[:20]:
        preview = data[offset:offset+min(16, length)]
        ascii_preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in preview)
        print(f"  +0x{offset:06x}: {length} 字节 - '{ascii_preview}'")
    if len(nonzero_regions) > 20:
        print(f"  ... 还有 {len(nonzero_regions) - 20} 个区域")

def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'analyze':
        analyze_misc(sys.argv[2])
    elif cmd in KNOWN_COMMANDS or cmd.startswith('boot-') or cmd.startswith('ffbm'):
        output_path = sys.argv[2]
        backup_path = None
        if '--from' in sys.argv:
            idx = sys.argv.index('--from')
            if idx + 1 < len(sys.argv):
                backup_path = sys.argv[idx + 1]
        make_bcb(cmd, output_path, backup_path)
    else:
        print(f"未知命令: {cmd}")
        print(f"已知命令: {', '.join(KNOWN_COMMANDS)}")
        print(__doc__)
        sys.exit(1)

if __name__ == '__main__':
    main()
