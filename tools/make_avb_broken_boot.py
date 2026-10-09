#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
制作 AVB 签名破坏版 boot.img（用于测试解锁状态）
原理：修改 boot.img 中一个字节，导致 vbmeta 中的 boot 哈希不匹配。
如果设备已解锁（AVB 容忍），会尝试启动（可能卡 logo）；
如果设备未锁定（AVB enforcing），会直接进 fastboot 报错。

修改位置：偏移 0x10000（64KB，避开 boot header，落在 kernel 区域）
修改方式：将该字节取反（0x00<->0xFF，或其他值取反）
"""

import sys
import os

SRC = r"H:\xtcz10check\v1.0.1_dump\boot_v101.img"
DST = r"H:\xtcz10check\tools\boot_v101_avb_broken.img"
MODIFY_OFFSET = 0x10000  # 64KB 处，避开 header

def make_avb_broken_boot():
    # 检查源文件
    if not os.path.exists(SRC):
        print(f"[!] 源文件不存在: {SRC}")
        return None
    
    src_size = os.path.getsize(SRC)
    print(f"[*] 源文件: {SRC}")
    print(f"    大小: {src_size} 字节 ({src_size/1024/1024:.1f} MB)")
    
    if MODIFY_OFFSET >= src_size:
        print(f"[!] 修改偏移 0x{MODIFY_OFFSET:X} 超出文件大小")
        return None
    
    # 复制并修改一个字节
    print(f"[*] 复制文件到: {DST}")
    print(f"[*] 修改偏移: 0x{MODIFY_OFFSET:X} ({MODIFY_OFFSET} 字节处)")
    
    with open(SRC, "rb") as f_src:
        data = bytearray(f_src.read())
    
    # 记录原始值
    original = data[MODIFY_OFFSET]
    # 取反
    modified = original ^ 0xFF
    data[MODIFY_OFFSET] = modified
    
    print(f"    原始值: 0x{original:02X}")
    print(f"    修改后: 0x{modified:02X} (取反)")
    
    # 写入目标文件
    with open(DST, "wb") as f_dst:
        f_dst.write(data)
    
    dst_size = os.path.getsize(DST)
    print(f"[+] 已生成: {DST}")
    print(f"    大小: {dst_size} 字节")
    
    # 验证
    with open(DST, "rb") as f:
        f.seek(MODIFY_OFFSET)
        verify = f.read(1)[0]
    
    if verify == modified:
        print(f"[✓] 验证通过: 偏移 0x{MODIFY_OFFSET:X} = 0x{verify:02X}")
    else:
        print(f"[!] 验证失败: 期望 0x{modified:02X}, 实际 0x{verify:02X}")
    
    print()
    print("=" * 60)
    print("[*] 测试方法:")
    print("    1. 进入 bootloader 模式")
    print("    2. fastboot flash boot_a boot_v101_avb_broken.img")
    print("       (或通过 EDL/QFIL 刷入)")
    print("    3. fastboot reboot")
    print("    4. 观察设备行为:")
    print()
    print("    结果判断:")
    print("    ├─ 直接进 fastboot + 报错 → ❌ 未解锁 (AVB enforcing)")
    print("    ├─ 卡 logo / 震动 / 尝试启动 → ✅ 已解锁 (AVB 容忍)")
    print("    └─ 能进系统 → ✅ 已解锁 (且修改的字节不影响启动)")
    print()
    print("[!] 注意: 修改的是 kernel 区域，可能无法正常进系统。")
    print("    只要不直接进 fastboot，就说明 AVB 校验被容忍了。")
    print()
    print("[!] 测试完成后恢复原版 boot:")
    print("    fastboot flash boot_a H:\\xtcz10check\\v1.0.1_dump\\boot_v101.img")
    
    return DST

if __name__ == "__main__":
    make_avb_broken_boot()
