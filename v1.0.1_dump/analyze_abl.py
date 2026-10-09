import struct
import os
import re

abl_path = r'H:\xtcz10check\v1.0.1_dump\abl_v101.img'
author_abl_path = r'H:\xtcz10check\2\250803\abl.img'
results = []

def read_elf_info(path):
    """读取ELF基本信息"""
    f = open(path, 'rb')
    head = f.read(64)
    f.close()

    info = {}
    info['magic'] = head[:4]
    info['class'] = head[4]  # 1=32位, 2=64位
    info['endian'] = head[5]  # 1=小端
    info['type'] = struct.unpack_from('<H', head, 16)[0]
    info['machine'] = struct.unpack_from('<H', head, 18)[0]
    info['entry'] = struct.unpack_from('<I', head, 24)[0]
    info['phoff'] = struct.unpack_from('<I', head, 28)[0]
    info['shoff'] = struct.unpack_from('<I', head, 32)[0]
    info['phentsize'] = struct.unpack_from('<H', head, 42)[0]
    info['phnum'] = struct.unpack_from('<H', head, 44)[0]
    info['shentsize'] = struct.unpack_from('<H', head, 46)[0]
    info['shnum'] = struct.unpack_from('<H', head, 48)[0]
    return info

def search_strings(path, min_len=5):
    """搜索所有可打印字符串"""
    f = open(path, 'rb')
    data = f.read()
    f.close()

    strings = []
    current = b''
    for i, b in enumerate(data):
        if 32 <= b < 127:
            current += bytes([b])
        else:
            if len(current) >= min_len:
                try:
                    s = current.decode('ascii')
                    strings.append((i - len(current), s))
                except:
                    pass
            current = b''
    if len(current) >= min_len:
        try:
            s = current.decode('ascii')
            strings.append((len(data) - len(current), s))
        except:
            pass
    return strings

# 1. ELF 基本信息
results.append('=' * 60)
results.append('v1.0.1 abl.img ELF 基本信息')
results.append('=' * 60)
info = read_elf_info(abl_path)
results.append(f'  魔术字: {info["magic"]}')
results.append(f'  位数: {info["class"]} (1=32位, 2=64位)')
results.append(f'  字节序: {info["endian"]} (1=小端)')
results.append(f'  类型: {info["type"]} (2=ET_EXEC)')
results.append(f'  架构: {info["machine"]} (0x28=EM_ARM)')
results.append(f'  入口点: 0x{info["entry"]:08X}')
results.append(f'  程序头偏移: 0x{info["phoff"]:X} (数量={info["phnum"]})')
results.append(f'  节头偏移: 0x{info["shoff"]:X} (数量={info["shnum"]})')
size = os.path.getsize(abl_path)
results.append(f'  文件大小: {size} 字节 ({size/1024:.1f} KB)')

# 2. 搜索关键字符串
results.append('\n' + '=' * 60)
results.append('关键字符串搜索')
results.append('=' * 60)
strings = search_strings(abl_path, 5)

# 分类搜索
categories = {
    'AVB/校验相关': ['avb', 'AVB', 'verify', 'VERIFY', 'vbmeta', 'hash', 'signature', 'public_key', 'rollback'],
    '解锁/锁定相关': ['unlock', 'UNLOCK', 'lock', 'LOCK', 'oem', 'OEM', 'device_state', 'secure', 'SECURE', 'device_state', 'flashing'],
    '启动/槽位相关': ['slot', 'SLOT', 'boot', 'BOOT', 'fastboot', 'FASTBOOT', 'recovery', 'normal', 'bootable', 'boot_success'],
    '错误/提示相关': ['error', 'ERROR', 'fail', 'FAIL', 'invalid', 'denied', 'refuse', 'corrupt', 'mismatch'],
    '高通相关': ['qcom', 'QCOM', 'qualcomm', 'Qualcomm', 'sahara', 'firehose', 'edl', 'EDL', '9008'],
    '分区相关': ['boot', 'system', 'vendor', 'super', 'abl', 'xbl', 'misc', 'persist', 'userdata'],
}

for cat_name, keywords in categories.items():
    results.append(f'\n--- {cat_name} ---')
    found = []
    for offset, s in strings:
        for kw in keywords:
            if kw in s:
                found.append((offset, s))
                break
    # 去重并排序
    seen = set()
    unique = []
    for offset, s in found:
        if s not in seen:
            seen.add(s)
            unique.append((offset, s))
    for offset, s in unique[:30]:
        results.append(f'  @0x{offset:06X}: "{s}"')
    if len(unique) > 30:
        results.append(f'  ... 还有 {len(unique)-30} 个')

# 3. 搜索特定的函数名字符串（可能出现在字符串表中）
results.append('\n' + '=' * 60)
results.append('可能的函数名/符号（含avb/unlock/verify的字符串）')
results.append('=' * 60)
func_keywords = ['avb_', 'Avb', 'AVB_', 'verify', 'Verify', 'unlock', 'Unlock', 'is_', 'get_', 'set_', 'check', 'Check', 'validate', 'Validate', 'slot_', 'Slot']
found_funcs = []
for offset, s in strings:
    for kw in func_keywords:
        if kw in s and len(s) < 80:
            found_funcs.append((offset, s))
            break
seen = set()
for offset, s in found_funcs:
    if s not in seen:
        seen.add(s)
        results.append(f'  @0x{offset:06X}: "{s}"')

# 4. 和作者 abl 对比大小和头部
results.append('\n' + '=' * 60)
results.append('v1.0.1 abl vs 作者 v2.8.1 abl 对比')
results.append('=' * 60)
if os.path.exists(author_abl_path):
    author_size = os.path.getsize(author_abl_path)
    author_info = read_elf_info(author_abl_path)
    results.append(f'  v1.0.1: 大小={size} 入口=0x{info["entry"]:08X}')
    results.append(f'  作者v2.8.1: 大小={author_size} 入口=0x{author_info["entry"]:08X}')
    results.append(f'  大小差异: {author_size - size} 字节')

    # 对比前4KB的差异
    f1 = open(abl_path, 'rb')
    f2 = open(author_abl_path, 'rb')
    d1 = f1.read(4096)
    d2 = f2.read(4096)
    f1.close()
    f2.close()
    diff_count = sum(1 for a, b in zip(d1, d2) if a != b)
    results.append(f'  前4KB差异字节数: {diff_count} / 4096')

    # 搜索作者abl中的字符串，看有没有额外的patch痕迹
    author_strings = search_strings(author_abl_path, 5)
    v1_strings_set = set(s for _, s in strings)
    author_only = []
    for offset, s in author_strings:
        if s not in v1_strings_set and len(s) > 5:
            author_only.append((offset, s))
    results.append(f'\n  作者abl独有的字符串（可能是patch添加的）:')
    seen = set()
    for offset, s in author_only[:20]:
        if s not in seen:
            seen.add(s)
            results.append(f'    @0x{offset:06X}: "{s}"')
else:
    results.append('  作者abl路径不存在')

output = '\n'.join(results)
out_path = r'H:\xtcz10check\v1.0.1_dump\abl_analysis.txt'
open(out_path, 'w', encoding='utf-8').write(output)
print(f'分析完成，结果写入 {out_path}')
print(f'共找到 {len(strings)} 个字符串')
