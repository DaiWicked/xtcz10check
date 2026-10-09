#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试EDL USB连接"""
import sys
import usb.core
import usb.util

print("=== USB 设备枚举测试 ===")
print(f"Python: {sys.version}")
print(f"pyusb: {usb.__version__}")
print()

# 枚举所有USB设备
devs = list(usb.core.find(find_all=True))
print(f"找到 {len(devs)} 个USB设备:")
for d in devs:
    try:
        print(f"  VID:PID={d.idVendor:04x}:{d.idProduct:04x}, "
              f"bus={d.bus}, address={d.address}, "
              f"manufacturer={d.manufacturer}, product={d.product}")
    except Exception as e:
        print(f"  VID:PID={d.idVendor:04x}:{d.idProduct:04x}, error={e}")

print()
print("=== 尝试连接 05c6:9008 ===")
dev = usb.core.find(idVendor=0x05c6, idProduct=0x9008)
if dev is None:
    print("❌ 未找到 05c6:9008 设备")
else:
    print(f"✅ 找到设备: bus={dev.bus}, address={dev.address}")
    try:
        print(f"  manufacturer: {dev.manufacturer}")
        print(f"  product: {dev.product}")
        print(f"  serial: {dev.serial_number}")
    except Exception as e:
        print(f"  读取信息失败: {e}")
    
    # 尝试设置配置
    try:
        dev.set_configuration()
        print("✅ set_configuration() 成功")
    except Exception as e:
        print(f"❌ set_configuration() 失败: {e}")
    
    # 获取配置
    try:
        cfg = dev.get_active_configuration()
        print(f"✅ 当前配置: {cfg.bConfigurationValue}")
        print(f"  接口数: {cfg.bNumInterfaces}")
        for intf in cfg:
            print(f"  接口 {intf.bInterfaceNumber}: "
                  f"class={intf.bInterfaceClass}, "
                  f"subclass={intf.bInterfaceSubClass}, "
                  f"protocol={intf.bInterfaceProtocol}")
    except Exception as e:
        print(f"❌ 获取配置失败: {e}")

print()
print("=== 测试完成 ===")
