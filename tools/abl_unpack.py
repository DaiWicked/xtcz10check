#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
小天才(XTC) abl 解压工具
结构：ELF(ARM32容器) → UEFI Firmware Volume → FFS file(type=0x0B)
     → GUIDED section(EFI LZMA GUID) → LZMA 解压 → PE32+ ARM64 镜像
用法：
  python abl_unpack.py <abl.elf 或 abl.img> [输出目录]
  python abl_unpack.py decrypted_images/v1.0.1/abl.elf unpacked_abl/v1.0.1
输出：
  <name>_pe32.bin       解压后的 PE32+ ARM64 镜像（可直接拖进 Ghidra）
  <name>_strings.txt     可读字符串列表（长度>=8）
  <name>_info.txt        结构信息（ELF/FV/FFS/Section/PE 头信息）
"""
import os
import sys
import struct
import lzma
import hashlib
import re

# ============================================================
# 常量
# ============================================================
EFI_LZMA_GUID = bytes([0x98, 0x58, 0x4e, 0xee, 0x14, 0x39, 0x59, 0x42,
                        0x9d, 0x6e, 0xdc, 0x7b, 0xd7, 0x94, 0x03, 0xcf])
# 注意：GUID 在文件中是混合字节序，上面是 DeepSeek 脚本中检测到的实际字节
# 标准 EFI LZMA GUID = EE4E5898-3914-4259-9D6E-DC7BD79403CF

FFS_TYPE_FIRMWARE_VOLUME_IMAGE = 0x0B
SECTION_TYPE_GUIDED = 0x02


def parse_elf_header(data):
    """解析 ELF 头，返回程序头列表"""
    if data[:4] != b'\x7fELF':
        return None, "不是 ELF 文件"
    ei_class = data[4]  # 1=32位, 2=64位
    if ei_class != 1:
        return None, f"不是 32 位 ELF (class={ei_class})"
    phoff = struct.unpack_from('<I', data, 28)[0]
    phnum = struct.unpack_from('<H', data, 44)[0]
    phentsize = struct.unpack_from('<H', data, 42)[0]
    entry = struct.unpack_from('<I', data, 24)[0]

    phdrs = []
    for i in range(phnum):
        off = phoff + i * phentsize
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
            struct.unpack_from('<8I', data, off)
        phdrs.append(dict(type=p_type, offset=p_offset, vaddr=p_vaddr,
                           paddr=p_paddr, filesz=p_filesz, memsz=p_memsz,
                           flags=p_flags, align=p_align))
    return dict(entry=entry, phoff=phoff, phnum=phnum, phdrs=phdrs), None


def parse_fv_header(blob):
    """解析 UEFI Firmware Volume 头"""
    # ZeroVector (16B) + FileSystemGuid (16B) + FvLength (8B) + Signature (4B="_FVH")
    # + Attributes (4B) + HeaderLength (2B) + Checksum (2B) + ExtHeaderOffset (2B) + Reserved (1B) + Revision (1B)
    if blob[0:16] != b'\x00' * 16:
        return None, "ZeroVector 不匹配"
    fv_guid = blob[16:32]
    fv_length = struct.unpack_from('<Q', blob, 32)[0]
    signature = blob[40:44]
    if signature != b'_FVH':
        return None, f"FV 签名不匹配: {signature}"
    attributes = struct.unpack_from('<I', blob, 44)[0]
    header_len = struct.unpack_from('<H', blob, 48)[0]
    revision = blob[51]
    return dict(guid=fv_guid.hex(), length=fv_length, signature=signature.decode(),
                attributes=attributes, header_len=header_len, revision=revision), None


def find_ffs_files(blob, fv_header_len):
    """在 FV 中查找 FFS 文件"""
    files = []
    offset = fv_header_len
    while offset < len(blob) - 24:
        # FFS 文件头: Name(16B GUID) + IntegrityCheck(2B) + Type(1B) + Attributes(1B) + Size(3B) + State(1B)
        name = blob[offset:offset+16]
        if name == b'\xff' * 16:  # 空扇区
            offset += 8
            continue
        ftype = blob[offset+18]
        attributes = blob[offset+19]
        fsize = int.from_bytes(blob[offset+20:offset+23], 'little')
        state = blob[offset+23]
        if fsize == 0 or fsize > len(blob) - offset:
            break
        files.append(dict(offset=offset, name=name.hex(), type=ftype,
                          attributes=attributes, size=fsize, state=state,
                          data=blob[offset+24:offset+fsize]))
        offset += fsize
        # 8 字节对齐
        if offset % 8:
            offset += 8 - (offset % 8)
    return files


def parse_sections(ffs_data):
    """解析 FFS 文件中的 sections"""
    sections = []
    offset = 0
    while offset < len(ffs_data) - 4:
        # Section 头: Size(3B) + Type(1B)
        ssize = int.from_bytes(ffs_data[offset:offset+3], 'little')
        stype = ffs_data[offset+3]
        if ssize == 0 or ssize > len(ffs_data) - offset:
            break
        sdata = ffs_data[offset+4:offset+ssize]
        sections.append(dict(offset=offset, size=ssize, type=stype, data=sdata))
        offset += ssize
        # 4 字节对齐
        if offset % 4:
            offset += 4 - (offset % 4)
    return sections


def try_lzma_decompress(data):
    """尝试多种方式 LZMA 解压，返回 (解压数据, 信息)"""
    # 方式1: LZMA alone 格式（13 字节头）
    for start in range(0, min(64, len(data))):
        chunk = data[start:]
        if len(chunk) < 32:
            continue
        # FORMAT_ALONE
        try:
            out = lzma.LZMADecompressor(lzma.FORMAT_ALONE).decompress(chunk)
            if len(out) > 10000:
                return out, dict(mode='alone', start=start)
        except Exception:
            pass
        # FORMAT_ALONE 跳过 5 字节
        try:
            out = lzma.LZMADecompressor(lzma.FORMAT_ALONE).decompress(chunk[5:])
            if len(out) > 10000:
                return out, dict(mode='alone-5', start=start)
        except Exception:
            pass
        # RAW 格式（从首字节解析 lc/lp/pb）
        try:
            pr = chunk[0]
            if pr <= 224:
                lc = pr % 9
                r = pr // 9
                lp = r % 5
                pb = r // 5
                filt = [{'id': lzma.FILTER_LZMA1, 'lc': lc, 'lp': lp,
                         'pb': pb, 'dict_size': 1 << 24}]
                out = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filt).decompress(chunk[5:])
                if len(out) > 10000:
                    return out, dict(mode='raw5', start=start, lc=lc, lp=lp, pb=pb)
        except Exception:
            pass
    return None, {}


def extract_strings(data, min_len=8):
    """提取可读 ASCII 字符串"""
    strings = []
    current = bytearray()
    for b in data:
        if 32 <= b < 127:
            current.append(b)
        else:
            if len(current) >= min_len:
                strings.append(current.decode('ascii', errors='replace'))
            current = bytearray()
    if len(current) >= min_len:
        strings.append(current.decode('ascii', errors='replace'))
    return strings


def parse_pe_header(data):
    """解析 PE32+ 头信息"""
    info = {}
    if data[:2] != b'MZ':
        # 查找 MZ 位置
        mz_pos = data.find(b'MZ')
        if mz_pos < 0:
            return None, "未找到 MZ 头"
        data = data[mz_pos:]
        info['mz_offset'] = mz_pos
    info['mz'] = data[:2].decode()
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    info['pe_offset'] = pe_offset
    if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
        return info, "PE 签名不匹配"
    # COFF 头
    machine = struct.unpack_from('<H', data, pe_offset+4)[0]
    num_sections = struct.unpack_from('<H', data, pe_offset+6)[0]
    info['machine'] = machine
    info['machine_hex'] = f'0x{machine:04X}'
    info['num_sections'] = num_sections
    # Optional 头（PE32+）
    opt_magic = struct.unpack_from('<H', data, pe_offset+24)[0]
    info['opt_magic'] = f'0x{opt_magic:04X}'
    if opt_magic == 0x20B:  # PE32+
        info['type'] = 'PE32+'
        image_base = struct.unpack_from('<Q', data, pe_offset+24+24)[0]
        entry_point = struct.unpack_from('<I', data, pe_offset+24+16)[0]
        info['image_base'] = f'0x{image_base:X}'
        info['entry_point'] = f'0x{entry_point:X}'
    # 段表
    sections = []
    sec_off = pe_offset + 24 + (112 if opt_magic == 0x20B else 96)
    for i in range(num_sections):
        name = data[sec_off+i*40:sec_off+i*40+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize = struct.unpack_from('<I', data, sec_off+i*40+8)[0]
        vaddr = struct.unpack_from('<I', data, sec_off+i*40+12)[0]
        raw_size = struct.unpack_from('<I', data, sec_off+i*40+16)[0]
        raw_ptr = struct.unpack_from('<I', data, sec_off+i*40+20)[0]
        sections.append(dict(name=name, vsize=vsize, vaddr=vaddr,
                             raw_size=raw_size, raw_ptr=raw_ptr))
    info['sections'] = sections
    return info, None


def unpack_abl(input_path, output_dir=None):
    """解压 abl，返回 (成功, 信息)"""
    if not os.path.exists(input_path):
        return False, f"文件不存在: {input_path}"

    data = open(input_path, 'rb').read()
    basename = os.path.splitext(os.path.basename(input_path))[0]

    # 如果是加密的（前 4 字节不是 ELF），尝试自动解密
    if data[:4] != b'\x7fELF':
        print(f"  检测到加密文件，尝试自动解密前 32 字节...")
        from xtc_fw_decrypt import xor_data, LARGE_FILE_XOR_SIZE
        data = xor_data(data[:LARGE_FILE_XOR_SIZE]) + data[LARGE_FILE_XOR_SIZE:]
        if data[:4] != b'\x7fELF':
            return False, "解密后仍不是 ELF，可能不是 abl 文件或加密方式不同"

    # 1. 解析 ELF
    elf_info, err = parse_elf_header(data)
    if err:
        return False, f"ELF 解析失败: {err}"

    # 找到 PT_LOAD 段（type=1）
    pt_load = None
    for ph in elf_info['phdrs']:
        if ph['type'] == 1:  # PT_LOAD
            pt_load = ph
            break
    if not pt_load:
        return False, "未找到 PT_LOAD 段"

    fv_blob = data[pt_load['offset']:pt_load['offset']+pt_load['filesz']]
    print(f"  ELF: entry=0x{elf_info['entry']:X}, PT_LOAD @0x{pt_load['offset']:X} size=0x{pt_load['filesz']:X}")

    # 2. 解析 FV 头
    fv_info, err = parse_fv_header(fv_blob)
    if err:
        return False, f"FV 解析失败: {err}"
    print(f"  FV: length=0x{fv_info['length']:X}, header_len=0x{fv_info['header_len']:X}")

    # 3. 查找 FFS 文件
    ffs_files = find_ffs_files(fv_blob, fv_info['header_len'])
    fvi_file = None
    for f in ffs_files:
        if f['type'] == FFS_TYPE_FIRMWARE_VOLUME_IMAGE:
            fvi_file = f
            break
    if not fvi_file:
        return False, "未找到 FIRMWARE_VOLUME_IMAGE 类型的 FFS 文件"
    print(f"  FFS: type=0x{fvi_file['type']:02X}, size=0x{fvi_file['size']:X}")

    # 4. 解析 sections
    sections = parse_sections(fvi_file['data'])
    guided_section = None
    for s in sections:
        if s['type'] == SECTION_TYPE_GUIDED:
            guided_section = s
            break
    if not guided_section:
        return False, "未找到 GUIDED section"
    print(f"  Section: type=0x{guided_section['type']:02X}, size=0x{guided_section['size']:X}")

    # 5. LZMA 解压
    pe_data, lzma_info = try_lzma_decompress(guided_section['data'])
    if not pe_data:
        return False, "LZMA 解压失败"
    print(f"  LZMA: mode={lzma_info['mode']}, start={lzma_info['start']}, 解压后={len(pe_data)} 字节")

    # 6. 解析 PE 头
    pe_info, err = parse_pe_header(pe_data)
    if pe_info:
        print(f"  PE: machine={pe_info.get('machine_hex','?')} ({'ARM64' if pe_info.get('machine')==0xAA64 else 'unknown'}), "
              f"ImageBase={pe_info.get('image_base','?')}, EntryPoint={pe_info.get('entry_point','?')}")
        print(f"  段表: {', '.join(s['name'] for s in pe_info.get('sections', []))}")

    # 7. 提取字符串
    strings = extract_strings(pe_data)
    print(f"  字符串: {len(strings)} 条 (长度>=8)")

    # 8. 输出文件
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    else:
        output_dir = os.path.dirname(input_path) or '.'

    pe_path = os.path.join(output_dir, f"{basename}_pe32.bin")
    strings_path = os.path.join(output_dir, f"{basename}_strings.txt")
    info_path = os.path.join(output_dir, f"{basename}_info.txt")

    with open(pe_path, 'wb') as f:
        f.write(pe_data)

    with open(strings_path, 'w', encoding='utf-8') as f:
        for s in strings:
            f.write(s + '\n')

    with open(info_path, 'w', encoding='utf-8') as f:
        f.write(f"文件: {input_path}\n")
        f.write(f"原始大小: {len(data)} 字节\n")
        f.write(f"SHA256: {hashlib.sha256(data).hexdigest()}\n\n")
        f.write(f"=== ELF ===\n")
        f.write(f"Entry: 0x{elf_info['entry']:X}\n")
        f.write(f"PT_LOAD: offset=0x{pt_load['offset']:X}, vaddr=0x{pt_load['vaddr']:X}, filesz=0x{pt_load['filesz']:X}\n\n")
        f.write(f"=== UEFI Firmware Volume ===\n")
        f.write(f"Length: 0x{fv_info['length']:X}\n")
        f.write(f"HeaderLength: 0x{fv_info['header_len']:X}\n")
        f.write(f"GUID: {fv_info['guid']}\n\n")
        f.write(f"=== FFS File (FIRMWARE_VOLUME_IMAGE) ===\n")
        f.write(f"Offset: 0x{fvi_file['offset']:X}\n")
        f.write(f"Size: 0x{fvi_file['size']:X}\n")
        f.write(f"Name GUID: {fvi_file['name']}\n\n")
        f.write(f"=== GUIDED Section (LZMA) ===\n")
        f.write(f"Size: 0x{guided_section['size']:X}\n")
        f.write(f"解压模式: {lzma_info['mode']}\n")
        f.write(f"解压后大小: {len(pe_data)} 字节\n")
        f.write(f"SHA256: {hashlib.sha256(pe_data).hexdigest()}\n\n")
        if pe_info:
            f.write(f"=== PE32+ ===\n")
            f.write(f"Machine: {pe_info.get('machine_hex','?')}\n")
            f.write(f"ImageBase: {pe_info.get('image_base','?')}\n")
            f.write(f"EntryPoint: {pe_info.get('entry_point','?')}\n")
            f.write(f"Sections:\n")
            for s in pe_info.get('sections', []):
                f.write(f"  {s['name']:8s} VA=0x{s['vaddr']:08X} VSz=0x{s['vsize']:08X} "
                        f"RawPtr=0x{s['raw_ptr']:08X} RawSz=0x{s['raw_size']:08X}\n")

    print(f"\n  输出文件:")
    print(f"    PE32+ : {pe_path}")
    print(f"    字符串: {strings_path}")
    print(f"    信息  : {info_path}")

    return True, dict(pe_data=pe_data, strings=strings, pe_info=pe_info,
                      elf_info=elf_info, fv_info=fv_info, lzma_info=lzma_info,
                      output_files=[pe_path, strings_path, info_path])


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    target = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else None

    if os.path.isfile(target):
        print(f"解压: {target}")
        print("=" * 60)
        ok, info = unpack_abl(target, out_dir)
        print("=" * 60)
        if ok:
            print("成功!")
        else:
            print(f"失败: {info}")
            sys.exit(1)
    elif os.path.isdir(target):
        # 批量解压目录下的 abl 文件
        files = [f for f in os.listdir(target)
                 if f.lower().endswith(('.elf', '.img')) and 'abl' in f.lower()]
        print(f"批量解压目录: {target} ({len(files)} 个文件)")
        for f in sorted(files):
            fpath = os.path.join(target, f)
            print(f"\n{'='*60}")
            print(f"解压: {f}")
            print("=" * 60)
            ok, info = unpack_abl(fpath, out_dir)
            if not ok:
                print(f"  跳过: {info}")
    else:
        print(f"路径不存在: {target}")
        sys.exit(1)


if __name__ == '__main__':
    main()
