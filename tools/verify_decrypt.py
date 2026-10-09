#!/usr/bin/env python3
"""验证解密后的镜像与设备 dump 一致性"""
import hashlib
import os

ROOT = r'H:\xtcz10check'
DEC = os.path.join(ROOT, 'decrypted_images', 'v1.0.1')
DUMP = os.path.join(ROOT, 'v1.0.1_dump')

pairs = [
    ('abl.elf', 'abl_v101.img', 'abl'),
    ('vbmeta.img', 'vbmeta_v101.img', 'vbmeta'),
    ('vbmeta_system.img', 'vbmeta_system_v101.img', 'vbmeta_system'),
    ('boot.img', 'boot_v101.img', 'boot'),
]

for fw_name, dump_name, label in pairs:
    fw_path = os.path.join(DEC, fw_name)
    dump_path = os.path.join(DUMP, dump_name)
    if not os.path.exists(fw_path):
        print(f'[{label}] 解密文件不存在: {fw_path}')
        continue
    if not os.path.exists(dump_path):
        print(f'[{label}] dump 文件不存在: {dump_path}')
        continue
    fw = open(fw_path, 'rb').read()
    dump = open(dump_path, 'rb').read()
    n = min(len(fw), len(dump))
    same = fw[:n] == dump[:n]
    fw_hash = hashlib.sha256(fw[:n]).hexdigest()[:16]
    dump_hash = hashlib.sha256(dump[:n]).hexdigest()[:16]
    print(f'[{label}] fw={len(fw)}B dump={len(dump)}B compare={n}B')
    print(f'  fw_hash  = {fw_hash}')
    print(f'  dump_hash= {dump_hash}')
    print(f'  一致: {same}')
    if not same:
        diffs = [i for i in range(min(n, 1000)) if fw[i] != dump[i]]
        print(f'  前1000字节差异数: {len(diffs)}, 前几个偏移: {[hex(x) for x in diffs[:8]]}')
    print()
