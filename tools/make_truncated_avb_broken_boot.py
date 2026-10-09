#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成正确大小的 AVB 破坏版 boot.img（截断到分区大小）
boot_a 分区大小 = 0x6000000 = 100663296 字节
原版 dump 镜像 = 100663387 字节（多了 91 字节，需要截断）
"""

import os

SRC = r"H:\xtcz10check\v1.0.1_dump\boot_v101.img"
DST = r"H:\xtcz10check\tools\boot_v101_avb_broken_truncated.img"
PARTITION_SIZE = 0x6000000  # 100663296 字节
MODIFY_OFFSET = 0x10000  # 64KB 处修改一个字节

def make_truncated_avb_broken_boot():
    src_size = os.path.getsize(SRC)
    print(f"[*] 源文件大小: {src_size} 字节")
    print(f"[*] 分区大小:   {PARTITION_SIZE} 字节 (0x{PARTITION_SIZE:X})")
    print(f"[*] 差值:       {src_size - PARTITION_SIZE} 字节（将被截断）")
    
    with open(SRC, "rb") as f:
        data = bytearray(f.read(PARTITION_SIZE))  # 只读取分区大小的数据
    
    print(f"[*] 截断后大小: {len(data)} 字节")
    
    # 修改一个字节破坏 AVB 签名
    original = data[MODIFY_OFFSET]
    data[MODIFY_OFFSET] = original ^ 0xFF
    print(f"[*] 修改偏移 0x{MODIFY_OFFSET:X}: 0x{original:02X} -> 0x{data[MODIFY_OFFSET]:02X}")
    
    with open(DST, "wb") as f:
        f.write(data)
    
    dst_size = os.path.getsize(DST)
    print(f"[+] 已生成: {DST}")
    print(f"    大小: {dst_size} 字节 (0x{dst_size:X})")
    
    if dst_size == PARTITION_SIZE:
        print(f"[✓] 大小匹配分区大小")
    else:
        print(f"[!] 大小不匹配！")
    
    print()
    print("=" * 60)
    print("[*] 写入命令（QMMI adb root）:")
    print(f"    adb push {DST} /sdcard/")
    print(f"    adb shell dd if=/sdcard/boot_v101_avb_broken_truncated.img of=/dev/block/by-name/boot_a")
    print("    adb reboot")
    print()
    print("[*] 恢复原版 boot:")
    print("    adb push H:\\xtcz10check\\v1.0.1_dump\\boot_v101.img /sdcard/")
    print("    adb shell dd if=/sdcard/boot_v101.img of=/dev/block/by-name/boot_a")
    print("    （注意：原版也是 100663387 字节，dd 会报 No space left，但前 100663296 字节已写入）")
    print("    或者用截断版恢复：先做一个原版截断版")

if __name__ == "__main__":
    make_truncated_avb_broken_boot()
