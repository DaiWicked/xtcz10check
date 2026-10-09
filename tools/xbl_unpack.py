#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
小天才(XTC) XBL 解包工具（通用 UEFI FV/FFS/LZMA 扫描器）

XBL 结构比 abl 复杂，可能包含多个 UEFI Firmware Volume 和多个 FFS 文件。
本工具扫描整个文件，找出所有 FV，解压所有 LZMA 压缩的 PE32+ 镜像。

结构：ELF(ARM64/AArch32) → 多个 UEFI FV → 多个 FFS file
     → FFS(type=0x0B) → GUIDED section(EFI LZMA) → LZMA 解压 → PE32+

用法：
  python xbl_unpack.py <xbl.elf> [输出目录]
  python xbl_unpack.py decrypted_images/v1.0.1/xbl.elf unpacked_xbl/v1.0.1

输出：
  fv_<n>_ffs_<m>_pe32.bin   解压后的 PE32+ 镜像
  fv_<n>_ffs_<m>_strings.txt 可读字符串列表
  xbl_unpack_info.txt         完整结构信息（所有 FV/FFS/Section）
"""
import os
import sys
import struct
import lzma

# ============================================================
# 常量
# ============================================================
EFI_LZMA_GUID = bytes([0x98, 0x58, 0x4e, 0xee, 0x14, 0x39, 0x59, 0x42,
                        0x9d, 0x6e, 0xdc, 0x7b, 0xd7, 0x94, 0x03, 0xcf])

FFS_TYPE_FIRMWARE_VOLUME_IMAGE = 0x0B
SECTION_TYPE_GUIDED = 0x02
SECTION_TYPE_PE32 = 0x10
SECTION_TYPE_PE32_PLUS = 0x11

FV_SIGNATURE = b'_FVH'
FV_HEADER_MIN_SIZE = 56


def guid_to_string(guid_bytes):
    """将 16 字节 GUID 转换为标准字符串"""
    if len(guid_bytes) < 16:
        return guid_bytes.hex()
    d1 = struct.unpack_from('<I', guid_bytes, 0)[0]
    d2 = struct.unpack_from('<H', guid_bytes, 4)[0]
    d3 = struct.unpack_from('<H', guid_bytes, 6)[0]
    d4 = guid_bytes[8:16].hex().upper()
    return f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[0:4]}-{d4[4:]}"


def parse_elf_program_headers(data):
    """解析 ELF 程序头，返回所有加载段的数据"""
    if data[:4] != b'\x7fELF':
        return [], "不是 ELF 文件"
    
    ei_class = data[4]  # 1=32位, 2=64位
    
    if ei_class == 1:
        # 32位 ELF
        phoff = struct.unpack_from('<I', data, 28)[0]
        phnum = struct.unpack_from('<H', data, 44)[0]
        phentsize = struct.unpack_from('<H', data, 42)[0]
        entry = struct.unpack_from('<I', data, 24)[0]
        fmt = '<8I'
    else:
        # 64位 ELF
        phoff = struct.unpack_from('<Q', data, 32)[0]
        phnum = struct.unpack_from('<H', data, 56)[0]
        phentsize = struct.unpack_from('<H', data, 54)[0]
        entry = struct.unpack_from('<Q', data, 24)[0]
        fmt = '<IIQQQQQQ'  # type, flags, offset, vaddr, paddr, filesz, memsz, align
    
    segments = []
    for i in range(phnum):
        off = phoff + i * phentsize
        if ei_class == 1:
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
                struct.unpack_from(fmt, data, off)
        else:
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                struct.unpack_from(fmt, data, off)
        
        if p_type == 1 and p_filesz > 0:  # PT_LOAD
            seg_data = data[p_offset:p_offset + p_filesz]
            segments.append(dict(index=i, offset=p_offset, vaddr=p_vaddr,
                                 size=p_filesz, data=seg_data))
    
    return segments, f"ELF{ei_class*32}, entry=0x{entry:X}, {len(segments)} load segments"


def find_fv_headers(blob):
    """在数据块中扫描所有 UEFI FV 头"""
    fvs = []
    offset = 0
    while offset < len(blob) - FV_HEADER_MIN_SIZE:
        # FV 头以 16 字节零开始，然后是 FileSystemGuid(16B)，然后 FvLength(8B)，然后 "_FVH"(4B)
        if blob[offset:offset+16] == b'\x00' * 16:
            signature_pos = offset + 40
            if signature_pos + 4 <= len(blob) and blob[signature_pos:signature_pos+4] == FV_SIGNATURE:
                fv_length = struct.unpack_from('<Q', blob, offset + 32)[0]
                fv_guid = blob[offset+16:offset+32]
                header_len = struct.unpack_from('<H', blob, offset + 48)[0]
                if 0 < fv_length <= len(blob) - offset and header_len >= FV_HEADER_MIN_SIZE:
                    fvs.append(dict(offset=offset, length=fv_length, guid=fv_guid,
                                     header_len=header_len, data=blob[offset:offset+fv_length]))
                    offset += fv_length
                    continue
        offset += 8  # 8 字节对齐扫描
    return fvs


def parse_ffs_files(fv_data, fv_header_len):
    """在 FV 中解析所有 FFS 文件"""
    files = []
    offset = fv_header_len
    fv_len = len(fv_data)
    
    while offset < fv_len - 24:
        # FFS 文件头: Name(16B GUID) + IntegrityCheck(2B) + Type(1B) + Attributes(1B) + Size(3B) + State(1B)
        name_guid = fv_data[offset:offset+16]
        
        # 跳过填充（全 FF 或全 0）
        if name_guid == b'\xff' * 16 or name_guid == b'\x00' * 16:
            offset += 8
            continue
        
        ffs_type = fv_data[offset + 18]
        ffs_attr = fv_data[offset + 19]
        # Size 是 3 字节小端
        ffs_size = fv_data[offset + 20] | (fv_data[offset + 21] << 8) | (fv_data[offset + 22] << 16)
        ffs_state = fv_data[offset + 23]
        
        if ffs_size < 24 or ffs_size > fv_len - offset:
            offset += 8
            continue
        
        ffs_data = fv_data[offset:offset + ffs_size]
        files.append(dict(offset=offset, size=ffs_size, guid=name_guid,
                          ftype=ffs_type, attr=ffs_attr, state=ffs_state,
                          data=ffs_data, header_size=24))
        
        offset += ffs_size
        # 8 字节对齐
        while offset % 8 != 0 and offset < fv_len:
            offset += 1
    
    return files


def parse_sections(ffs_data, ffs_header_size):
    """解析 FFS 文件中的所有 section"""
    sections = []
    offset = ffs_header_size
    data_len = len(ffs_data)
    
    while offset < data_len - 4:
        # Section 头: Size(3B) + Type(1B)，如果 Size=0xFFFFFF 则使用扩展大小(4B)
        sec_size = ffs_data[offset] | (ffs_data[offset+1] << 8) | (ffs_data[offset+2] << 16)
        sec_type = ffs_data[offset + 3]
        
        header_size = 4
        if sec_size == 0xFFFFFF:
            # 扩展大小
            sec_size = struct.unpack_from('<I', ffs_data, offset + 4)[0]
            header_size = 8
        
        if sec_size < header_size or sec_size > data_len - offset:
            break
        
        sec_data = ffs_data[offset:offset + sec_size]
        sections.append(dict(offset=offset, size=sec_size, stype=sec_type,
                             header_size=header_size, data=sec_data))
        
        offset += sec_size
        # 4 字节对齐
        while offset % 4 != 0 and offset < data_len:
            offset += 1
    
    return sections


def try_lzma_decompress(data):
    """尝试 LZMA 解压（支持 alone 格式）"""
    # LZMA alone 格式: 5 字节属性 + 8 字节未压缩大小 + 压缩数据
    # 属性通常在偏移 0，也可能在偏移 12（前面有 GUIDED section 头）
    
    candidates = []
    # 尝试不同的起始偏移
    for start in [0, 4, 8, 12, 16]:
        if start + 13 > len(data):
            continue
        # 检查 LZMA 属性字节（高 3 位是 lc, 接下来 3 位是 lp, 低 2 位是 pb）
        # 常见值: 0x5D (lc=3, lp=0, pb=2)
        props = data[start]
        if (props & 0xC0) == 0 and props <= 0xE0:  # 合理的属性值
            candidates.append(start)
    
    for start in candidates:
        try:
            # 构造 LZMA alone 格式输入
            alone_data = data[start:]
            decompressed = lzma.decompress(alone_data, format=lzma.FORMAT_ALONE)
            return decompressed, f"LZMA alone @ offset {start}, props=0x{props:02X}"
        except Exception:
            continue
    
    # 尝试 raw LZMA2
    try:
        decompressed = lzma.decompress(data, format=lzma.FORMAT_XZ)
        return decompressed, "XZ format"
    except Exception:
        pass
    
    return None, None


def extract_strings(data, min_length=8):
    """提取可读 ASCII 字符串"""
    strings = []
    current = []
    for b in data:
        if 0x20 <= b < 0x7F:
            current.append(chr(b))
        else:
            if len(current) >= min_length:
                strings.append(''.join(current))
            current = []
    if len(current) >= min_length:
        strings.append(''.join(current))
    return strings


def unpack_xbl(input_path, output_dir):
    """解包 XBL"""
    print(f"[*] 输入: {input_path}")
    print(f"[*] 输出目录: {output_dir}")
    os.makedirs(output_dir, exist_ok=True)
    
    with open(input_path, 'rb') as f:
        data = f.read()
    
    print(f"[*] 文件大小: {len(data)} 字节 ({len(data)/1024/1024:.1f} MB)")
    
    # 1. 解析 ELF
    segments, elf_info = parse_elf_program_headers(data)
    print(f"[*] ELF: {elf_info}")
    
    # 2. 合并所有 load segment 数据用于扫描
    # 同时也扫描整个文件（FV 可能在任何位置）
    all_fvs = []
    
    # 扫描整个文件找 FV
    print("[*] 扫描整个文件中的 UEFI FV...")
    fvs = find_fv_headers(data)
    print(f"    找到 {len(fvs)} 个 FV")
    
    for i, fv in enumerate(fvs):
        print(f"    FV[{i}]: offset=0x{fv['offset']:X}, size=0x{fv['length']:X}, "
              f"GUID={guid_to_string(fv['guid'])}")
        
        # 解析 FFS 文件
        ffs_files = parse_ffs_files(fv['data'], fv['header_len'])
        print(f"      包含 {len(ffs_files)} 个 FFS 文件")
        
        for j, ffs in enumerate(ffs_files):
            type_names = {0x01: 'RAW', 0x02: 'FREEFORM', 0x03: 'SEC_CORE',
                          0x04: 'PEI_CORE', 0x05: 'DXE_CORE', 0x06: 'PEIM',
                          0x07: 'DRIVER', 0x08: 'COMBINED_PEIM_DRIVER',
                          0x09: 'APPLICATION', 0x0A: 'MM', 0x0B: 'FV_IMAGE',
                          0x0C: 'COMBINED_MM_DXE', 0x0D: 'SMM_CORE', 0x0F: 'SMM'}
            type_name = type_names.get(ffs['ftype'], f"TYPE_{ffs['ftype']:02X}")
            
            # 解析 sections
            sections = parse_sections(ffs['data'], ffs['header_size'])
            
            # 找 GUIDED section (LZMA)
            lzma_section = None
            pe_section = None
            for sec in sections:
                if sec['stype'] == SECTION_TYPE_GUIDED:
                    lzma_section = sec
                elif sec['stype'] in (SECTION_TYPE_PE32, SECTION_TYPE_PE32_PLUS):
                    pe_section = sec
            
            status = ""
            if lzma_section:
                # 尝试解压
                # GUIDED section 数据: SectionGuid(16B) + SectionAttributes(4B) + 压缩数据
                guided_data = lzma_section['data'][lzma_section['header_size']:]
                if len(guided_data) > 20:
                    decompressed, info = try_lzma_decompress(guided_data)
                    if decompressed:
                        # 输出解压后的 PE
                        out_name = f"fv{i}_ffs{j}_{type_name}_pe32.bin"
                        out_path = os.path.join(output_dir, out_name)
                        with open(out_path, 'wb') as f:
                            f.write(decompressed)
                        
                        # 提取字符串
                        strs = extract_strings(decompressed)
                        str_path = os.path.join(output_dir, out_name.replace('.bin', '_strings.txt'))
                        with open(str_path, 'w', encoding='utf-8', errors='replace') as f:
                            f.write(f"# {out_name}\n")
                            f.write(f"# 解压后大小: {len(decompressed)} 字节\n")
                            f.write(f"# 字符串数量: {len(strs)}\n\n")
                            for s in strs:
                                f.write(s + '\n')
                        
                        status = f"✅ 解压成功 -> {out_name} ({len(decompressed)}B, {info})"
                        
                        # 检查是否是 PE
                        mz_pos = decompressed.find(b'MZ')
                        if mz_pos >= 0:
                            status += f", MZ@0x{mz_pos:X}"
                    else:
                        status = "⚠️ LZMA 解压失败"
                else:
                    status = "⚠️ GUIDED section 数据太小"
            elif pe_section:
                # 直接是 PE（未压缩）
                pe_data = pe_section['data'][pe_section['header_size']:]
                out_name = f"fv{i}_ffs{j}_{type_name}_pe32.bin"
                out_path = os.path.join(output_dir, out_name)
                with open(out_path, 'wb') as f:
                    f.write(pe_data)
                status = f"✅ 直接 PE -> {out_name} ({len(pe_data)}B)"
            else:
                status = f"({len(sections)} sections, 无 LZMA/PE)"
            
            guid_str = guid_to_string(ffs['guid'])
            print(f"      FFS[{j}]: type=0x{ffs['ftype']:02X}({type_name}), "
                  f"size=0x{ffs['size']:X}, GUID={guid_str}")
            print(f"               {status}")
            
            all_fvs.append(dict(fv_index=i, ffs_index=j, fv_offset=fv['offset'],
                                 ffs_offset=fv['offset'] + ffs['offset'],
                                 ffs_type=ffs['ftype'], type_name=type_name,
                                 guid=guid_str, size=ffs['size'], status=status))
    
    # 输出结构信息
    info_path = os.path.join(output_dir, "xbl_unpack_info.txt")
    with open(info_path, 'w', encoding='utf-8') as f:
        f.write(f"XBL 解包信息\n")
        f.write(f"{'='*60}\n")
        f.write(f"输入文件: {input_path}\n")
        f.write(f"文件大小: {len(data)} 字节\n")
        f.write(f"ELF: {elf_info}\n")
        f.write(f"FV 数量: {len(fvs)}\n")
        f.write(f"FFS 文件总数: {len(all_fvs)}\n\n")
        
        for item in all_fvs:
            f.write(f"FV[{item['fv_index']}] FFS[{item['ffs_index']}]:\n")
            f.write(f"  类型: 0x{item['ffs_type']:02X} ({item['type_name']})\n")
            f.write(f"  GUID: {item['guid']}\n")
            f.write(f"  大小: 0x{item['size']:X}\n")
            f.write(f"  FV偏移: 0x{item['fv_offset']:X}\n")
            f.write(f"  FFS偏移: 0x{item['ffs_offset']:X}\n")
            f.write(f"  状态: {item['status']}\n\n")
    
    print(f"\n[+] 解包完成！输出目录: {output_dir}")
    print(f"[+] 结构信息: {info_path}")
    
    # 统计解压出的 PE 文件
    pe_files = [f for f in os.listdir(output_dir) if f.endswith('_pe32.bin')]
    print(f"[+] 解压出 {len(pe_files)} 个 PE32+ 镜像:")
    for pf in sorted(pe_files):
        pf_path = os.path.join(output_dir, pf)
        pf_size = os.path.getsize(pf_path)
        print(f"    {pf} ({pf_size} 字节, {pf_size/1024:.1f} KB)")
    
    return output_dir


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python xbl_unpack.py <xbl.elf> [输出目录]")
        sys.exit(1)
    
    input_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "unpacked_xbl"
    
    if not os.path.isabs(input_path):
        input_path = os.path.abspath(input_path)
    if not os.path.isabs(output_dir):
        output_dir = os.path.abspath(output_dir)
    
    unpack_xbl(input_path, output_dir)
