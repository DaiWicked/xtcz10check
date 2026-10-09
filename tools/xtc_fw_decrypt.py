#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
小天才(XTC)固件全量解密工具
算法：固定 XOR 密钥流（256字节 key_table 双重 XOR，等效 16384 字节周期流）
规则（DeepSeek 2026-10-08 对照实验验证版）：
  - 文件 <= 32768 字节 (0x8000)：整个文件被 XOR 混淆
  - 文件 > 32768 字节：每个 1MB (0x100000) 块的头 32 字节被 XOR 混淆
    第 k 块（k=0,1,2,...，文件内块序号）用密钥流偏移 KS[(64*k) mod 16384 : +32]
    （加密器每处理一个 1MB 块，密钥流前进 64 字节，只消费 32 字节）
来源：MIO-KITCHEN xtc_recovery_helper.py + DeepSeek 已知明文对对照实验（v1.0.1 super 0差异/2.4GB）
用法：
  python xtc_fw_decrypt.py <固件目录或文件> [输出目录]
  python xtc_fw_decrypt.py ND03_V1.0.1 decrypted_images/v1.0.1
  python xtc_fw_decrypt.py abl.elf abl_decrypted.elf
"""
import os
import sys
import struct

# ============================================================
# 256 字节固定查找表（与 XML 解密完全相同）
# ============================================================
KEY_TABLE = bytes([
    0xF5, 0x89, 0x28, 0x66, 0x68, 0x3F, 0xB9, 0xED,
    0x7D, 0xDC, 0xCA, 0x7A, 0x37, 0x7B, 0xE0, 0xF9,
    0x04, 0xF8, 0xD2, 0xAE, 0x17, 0xCF, 0xC2, 0x61,
    0x08, 0x5D, 0x13, 0x90, 0x37, 0x0B, 0xC5, 0x3D,
    0x0F, 0xAA, 0xD6, 0x37, 0x28, 0x87, 0x92, 0x06,
    0xB4, 0x2E, 0x6B, 0xAF, 0x11, 0x36, 0x45, 0x5F,
    0x76, 0x2F, 0x19, 0x31, 0xC3, 0xDF, 0x72, 0xE8,
    0x90, 0xF6, 0x4F, 0x06, 0x6B, 0xE7, 0x28, 0x0F,
    0xD0, 0x90, 0x7C, 0xA1, 0x73, 0x2E, 0x39, 0x83,
    0x5F, 0x85, 0xAB, 0x07, 0x87, 0x84, 0x13, 0x29,
    0x58, 0x26, 0x7B, 0x7A, 0xF6, 0x2F, 0xD9, 0x93,
    0x43, 0x87, 0x37, 0xB0, 0x54, 0x15, 0xA5, 0x9D,
    0xC9, 0x0B, 0x66, 0xA1, 0xDF, 0x2D, 0x27, 0x26,
    0x12, 0x16, 0x65, 0xC3, 0x04, 0x98, 0x2C, 0xD4,
    0xDF, 0x64, 0x22, 0x5E, 0xE8, 0xE7, 0xE2, 0x56,
    0xE3, 0x9E, 0xE5, 0x75, 0x3D, 0x9A, 0x82, 0x74,
    0xD1, 0x54, 0xDE, 0xFA, 0xCA, 0x44, 0x1D, 0x9E,
    0xA2, 0xA7, 0xB1, 0xC1, 0xC6, 0xD7, 0x16, 0xF9,
    0x4E, 0xA7, 0x03, 0x4B, 0x03, 0x40, 0x9F, 0x0F,
    0x13, 0x98, 0xC9, 0x41, 0x0F, 0xD0, 0x24, 0x18,
    0xD0, 0x90, 0x7C, 0xA1, 0x73, 0x2E, 0x39, 0x83,
    0x5F, 0x85, 0xAB, 0x07, 0x87, 0x84, 0x13, 0x29,
    0x58, 0x26, 0x7B, 0x7A, 0xF6, 0x2F, 0xD9, 0x93,
    0x43, 0x87, 0x37, 0xB0, 0x54, 0x15, 0xA5, 0x9D,
    0x14, 0x07, 0xA8, 0x76, 0x02, 0xD4, 0xF7, 0x1D,
    0x22, 0xB4, 0xC9, 0x17, 0x21, 0xF8, 0x3E, 0x39,
    0x14, 0xE1, 0x3D, 0x13, 0x5D, 0x81, 0x66, 0x61,
    0xA6, 0x9F, 0x88, 0x45, 0xB9, 0x00, 0x53, 0xB3,
    0x9B, 0x0A, 0x79, 0x13, 0x60, 0x82, 0x93, 0x0A,
    0x91, 0x27, 0x8F, 0xC7, 0x16, 0xFC, 0xE2, 0x9E,
    0x42, 0x3D, 0xED, 0xF6, 0x0A, 0x87, 0xF9, 0x10,
    0xC0, 0x7F, 0x73, 0x3D, 0x59, 0x64, 0x6A, 0x93,
])

KEYSTREAM_PERIOD = 16384  # 密钥流周期（256 组 index/count 重置）
LARGE_FILE_THRESHOLD = 0x8000  # 32768 字节
BLOCK_SIZE = 0x100000  # 1MB 块大小
BLOCK_XOR_SIZE = 32  # 每个块只 XOR 前 32 字节
BLOCK_KEYSTREAM_STEP = 64  # 每处理一个块，密钥流前进 64 字节（只消费 32）

# 已知明文 magic（用于验证解密结果）
KNOWN_MAGICS = [
    (b'\x7fELF', 'ELF'),
    (b'ANDROID!', 'Android boot'),
    (b'AVB0', 'AVB vbmeta'),
    (b'<?xml', 'XML'),
    (b'\xeb\x3c\x90\x4d\x53\x44\x4f\x53', 'FAT (MSDOS5.0)'),
    (b'\xd7\xb7\xab\x1e', 'DTBO table'),
    (b'MZ', 'PE/DOS'),
    (b'\x00' * 4, 'all-zero (可能未初始化分区)'),
]


def make_keystream(length=KEYSTREAM_PERIOD, index0=41, count0=41):
    """
    生成固定 XOR 密钥流。
    算法：双重 XOR，key_table[cur%64] ^ key_table[index]
    每 64 字节 index+1，count+1；count 达 256 后重置为 0
    """
    ks = bytearray(length)
    index = index0
    count = count0
    for cur in range(length):
        idx = cur % 64
        ks[cur] = KEY_TABLE[idx] ^ KEY_TABLE[index]
        if idx == 0:
            count += 1
            index += 1
            if count >= 256:
                count = 0
                index = 0
    return bytes(ks)


# 预计算一个周期的密钥流
KEYSTREAM = make_keystream(KEYSTREAM_PERIOD)


def xor_data(data, offset=0):
    """对数据应用密钥流 XOR（offset 用于大文件前 32 字节之后保持不变）"""
    n = len(data)
    result = bytearray(n)
    for i in range(n):
        result[i] = data[i] ^ KEYSTREAM[(offset + i) % KEYSTREAM_PERIOD]
    return bytes(result)


def detect_magic(data):
    """检测数据的明文 magic，返回 (magic, description) 或 (None, 'unknown')"""
    for magic, desc in KNOWN_MAGICS:
        if data[:len(magic)] == magic:
            return magic, desc
    return None, 'unknown'


def is_already_plaintext(data):
    """判断文件是否已经是明文（不需要解密）"""
    magic, desc = detect_magic(data)
    return magic is not None and desc != 'unknown' and desc != 'all-zero (可能未初始化分区)'


def decrypt_file(input_path, output_path=None, verbose=True):
    """
    解密单个固件文件。
    规则：
      - 文件 <= 32768 字节：整个文件 XOR
      - 文件 > 32768 字节：只有前 32 字节 XOR，其余保持不变（流式处理，避免大文件内存溢出）
    返回 (success, message)
    """
    import shutil

    if not os.path.exists(input_path):
        return False, f"文件不存在: {input_path}"

    filesize = os.path.getsize(input_path)
    target = output_path if output_path else input_path
    os.makedirs(os.path.dirname(target) or '.', exist_ok=True)

    # 先读前 32 字节判断是否已明文
    with open(input_path, 'rb') as f:
        header32 = f.read(32)

    if is_already_plaintext(header32):
        magic, desc = detect_magic(header32)
        if output_path and output_path != input_path:
            shutil.copy2(input_path, target)
        if verbose:
            print(f"  [跳过-已明文] {os.path.basename(input_path)} ({filesize}B) -> {desc}")
        return True, f"already plaintext ({desc})"

    # 确定 XOR 范围
    if filesize <= LARGE_FILE_THRESHOLD:
        # 小文件：全文 XOR（全部读入内存）
        xor_size = filesize
        rule = "full-file"
        with open(input_path, 'rb') as f:
            raw = f.read()
        decrypted = xor_data(raw)
        with open(target, 'wb') as f:
            f.write(decrypted)
        verify_data = decrypted[:32]
    else:
        # 大文件：每个 1MB 块的头 32 字节 XOR，其余流式复制（避免内存溢出）
        # 第 k 块用密钥流偏移 (64*k) mod 16384
        rule = "per-1MB-block-32B"
        block_index = 0
        with open(input_path, 'rb') as fin, open(target, 'wb') as fout:
            while True:
                chunk = fin.read(BLOCK_SIZE)
                if not chunk:
                    break
                chunk_len = len(chunk)
                xor_len = min(BLOCK_XOR_SIZE, chunk_len)
                if xor_len > 0:
                    ks_offset = (BLOCK_KEYSTREAM_STEP * block_index) % KEYSTREAM_PERIOD
                    header = bytearray(chunk[:xor_len])
                    for i in range(xor_len):
                        header[i] ^= KEYSTREAM[(ks_offset + i) % KEYSTREAM_PERIOD]
                    fout.write(bytes(header))
                    if chunk_len > xor_len:
                        fout.write(chunk[xor_len:])
                else:
                    fout.write(chunk)
                # 第一个块的解密结果用于验证
                if block_index == 0:
                    verify_data = bytes(header) if xor_len > 0 else chunk[:32]
                block_index += 1

    # 验证解密结果
    magic, desc = detect_magic(verify_data)

    if verbose:
        status = "OK" if magic else "??"
        print(f"  [{status}] {os.path.basename(input_path)} ({filesize}B, {rule}) -> {desc}")
        if not magic:
            print(f"       first 16 bytes: {verify_data[:16].hex(' ')}")

    return magic is not None, f"decrypted ({desc}, {rule})"


def decrypt_directory(input_dir, output_dir=None, verbose=True):
    """解密目录下所有文件"""
    if not os.path.isdir(input_dir):
        print(f"目录不存在: {input_dir}")
        return

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    files = sorted([f for f in os.listdir(input_dir)
                    if os.path.isfile(os.path.join(input_dir, f))])

    print(f"\n{'='*60}")
    print(f"解密目录: {input_dir}")
    print(f"输出目录: {output_dir or '(原地覆盖)'}")
    print(f"文件数量: {len(files)}")
    print(f"{'='*60}")

    success = 0
    skipped = 0
    failed = 0

    for fname in files:
        fpath = os.path.join(input_dir, fname)
        outpath = os.path.join(output_dir, fname) if output_dir else None
        ok, msg = decrypt_file(fpath, outpath, verbose=verbose)
        if ok:
            if 'already plaintext' in msg:
                skipped += 1
            else:
                success += 1
        else:
            failed += 1

    print(f"\n{'='*60}")
    print(f"完成: 解密成功={success}, 已明文跳过={skipped}, 失败={failed}")
    print(f"{'='*60}\n")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    target = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else None

    if os.path.isfile(target):
        # 单个文件
        out_file = out_dir if out_dir and (out_dir.endswith(('.elf', '.img', '.mbn', '.bin', '.xml')) or '.' in os.path.basename(out_dir)) else None
        if out_file is None and out_dir:
            out_file = os.path.join(out_dir, os.path.basename(target))
        ok, msg = decrypt_file(target, out_file)
        sys.exit(0 if ok else 1)
    elif os.path.isdir(target):
        decrypt_directory(target, out_dir)
    else:
        print(f"路径不存在: {target}")
        sys.exit(1)


if __name__ == '__main__':
    main()
