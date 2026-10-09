#!/usr/bin/env python3
"""
Android Boot Image Unpacker
支持 ANDROID! 头格式（v0/v1/v2/v3/v4）
"""
import struct
import os
import sys
import gzip
import lzma
import zlib

def align_to(value, alignment):
    return (value + alignment - 1) // alignment * alignment

def unpack_boot_image(image_path, output_dir):
    with open(image_path, 'rb') as f:
        data = f.read()
    
    # 检查 magic
    magic = data[0:8]
    if magic != b'ANDROID!':
        print(f"错误: 不是有效的 Android boot 镜像，magic={magic}")
        return False
    
    # 解析头部
    kernel_size = struct.unpack('<I', data[0x08:0x0C])[0]
    kernel_addr = struct.unpack('<I', data[0x0C:0x10])[0]
    ramdisk_size = struct.unpack('<I', data[0x10:0x14])[0]
    ramdisk_addr = struct.unpack('<I', data[0x14:0x18])[0]
    second_size = struct.unpack('<I', data[0x18:0x1C])[0]
    second_addr = struct.unpack('<I', data[0x1C:0x20])[0]
    tags_addr = struct.unpack('<I', data[0x20:0x24])[0]
    page_size = struct.unpack('<I', data[0x24:0x28])[0]
    header_version = struct.unpack('<I', data[0x28:0x2C])[0]
    
    # v3/v4 格式 page_size 可能为 0，使用默认 4096
    if page_size == 0:
        page_size = 4096
        print(f"注意: page_size=0，使用默认值 4096 (v3/v4 格式)")
    os_version = struct.unpack('<I', data[0x2C:0x30])[0]
    name = data[0x30:0x40].split(b'\x00')[0].decode('ascii', errors='replace')
    cmdline = data[0x40:0x240].split(b'\x00')[0].decode('ascii', errors='replace')
    
    print(f"=== Boot Image Info ===")
    print(f"Magic: {magic}")
    print(f"Header Version: {header_version}")
    print(f"Page Size: {page_size}")
    print(f"Kernel Size: {kernel_size} (0x{kernel_size:X})")
    print(f"Kernel Addr: 0x{kernel_addr:X}")
    print(f"Ramdisk Size: {ramdisk_size} (0x{ramdisk_size:X})")
    print(f"Ramdisk Addr: 0x{ramdisk_addr:X}")
    print(f"Second Size: {second_size}")
    print(f"Name: {name}")
    print(f"Cmdline: {cmdline}")
    print(f"OS Version: {os_version}")
    
    # 创建输出目录
    os.makedirs(output_dir, exist_ok=True)
    
    # 保存头部信息
    with open(os.path.join(output_dir, 'header_info.txt'), 'w') as f:
        f.write(f"Magic: {magic}\n")
        f.write(f"Header Version: {header_version}\n")
        f.write(f"Page Size: {page_size}\n")
        f.write(f"Kernel Size: {kernel_size}\n")
        f.write(f"Kernel Addr: 0x{kernel_addr:X}\n")
        f.write(f"Ramdisk Size: {ramdisk_size}\n")
        f.write(f"Ramdisk Addr: 0x{ramdisk_addr:X}\n")
        f.write(f"Second Size: {second_size}\n")
        f.write(f"Name: {name}\n")
        f.write(f"Cmdline: {cmdline}\n")
    
    # 计算各部分偏移
    kernel_offset = page_size  # 第一个 page 之后
    ramdisk_offset = kernel_offset + align_to(kernel_size, page_size)
    second_offset = ramdisk_offset + align_to(ramdisk_size, page_size)
    
    # 提取 kernel
    if kernel_size > 0:
        kernel_data = data[kernel_offset:kernel_offset + kernel_size]
        kernel_path = os.path.join(output_dir, 'kernel')
        with open(kernel_path, 'wb') as f:
            f.write(kernel_data)
        print(f"\nKernel 已保存: {kernel_path} ({len(kernel_data)} bytes)")
        
        # 检测 kernel 压缩格式
        if kernel_data[:2] == b'\x1f\x8b':
            print("  格式: gzip 压缩")
        elif kernel_data[:6] == b'\xfd7zXZ\x00':
            print("  格式: xz 压缩")
        elif kernel_data[:4] == b'\x89PNG':
            print("  格式: 未压缩（Image）")
    
    # 提取 ramdisk
    if ramdisk_size > 0:
        ramdisk_data = data[ramdisk_offset:ramdisk_offset + ramdisk_size]
        ramdisk_path = os.path.join(output_dir, 'ramdisk.cpio')
        
        # 检测压缩格式
        compression = None
        if ramdisk_data[:2] == b'\x1f\x8b':
            compression = 'gzip'
            ramdisk_path = os.path.join(output_dir, 'ramdisk.cpio.gz')
        elif ramdisk_data[:6] == b'\xfd7zXZ\x00':
            compression = 'xz'
            ramdisk_path = os.path.join(output_dir, 'ramdisk.cpio.xz')
        elif ramdisk_data[:4] == b'\x28\xb5\x2f\xfd':
            compression = 'zstd'
            ramdisk_path = os.path.join(output_dir, 'ramdisk.cpio.zst')
        elif ramdisk_data[:6] == b'\x04\x22\x4d\x18':
            compression = 'lz4'
            ramdisk_path = os.path.join(output_dir, 'ramdisk.cpio.lz4')
        
        with open(ramdisk_path, 'wb') as f:
            f.write(ramdisk_data)
        print(f"\nRamdisk 已保存: {ramdisk_path} ({len(ramdisk_data)} bytes)")
        print(f"  压缩格式: {compression or '未压缩'}")
        
        # 尝试解压 ramdisk
        if compression == 'gzip':
            try:
                decompressed = gzip.decompress(ramdisk_data)
                decompressed_path = os.path.join(output_dir, 'ramdisk.cpio')
                with open(decompressed_path, 'wb') as f:
                    f.write(decompressed)
                print(f"  已解压: {decompressed_path} ({len(decompressed)} bytes)")
                
                # 提取 cpio 内容
                extract_cpio(decompressed, os.path.join(output_dir, 'ramdisk'))
            except Exception as e:
                print(f"  解压失败: {e}")
        elif compression == 'xz':
            try:
                decompressed = lzma.decompress(ramdisk_data)
                decompressed_path = os.path.join(output_dir, 'ramdisk.cpio')
                with open(decompressed_path, 'wb') as f:
                    f.write(decompressed)
                print(f"  已解压: {decompressed_path} ({len(decompressed)} bytes)")
                extract_cpio(decompressed, os.path.join(output_dir, 'ramdisk'))
            except Exception as e:
                print(f"  解压失败: {e}")
    
    # 提取 second
    if second_size > 0:
        second_data = data[second_offset:second_offset + second_size]
        second_path = os.path.join(output_dir, 'second')
        with open(second_path, 'wb') as f:
            f.write(second_data)
        print(f"\nSecond 已保存: {second_path} ({len(second_data)} bytes)")
    
    print(f"\n=== 解包完成 ===")
    print(f"输出目录: {output_dir}")
    return True

def extract_cpio(cpio_data, output_dir):
    """提取 cpio 归档（newc 格式）"""
    os.makedirs(output_dir, exist_ok=True)
    offset = 0
    file_count = 0
    
    while offset < len(cpio_data):
        # cpio newc 头部 110 字节
        if offset + 110 > len(cpio_data):
            break
        
        header = cpio_data[offset:offset+110]
        magic = header[0:6]
        
        if magic != b'070701':
            # 可能是 TRAILER!!! 或结束
            break
        
        # 解析头部
        inode = int(header[6:14], 16)
        mode = int(header[14:22], 16)
        uid = int(header[22:30], 16)
        gid = int(header[30:38], 16)
        nlink = int(header[38:46], 16)
        mtime = int(header[46:54], 16)
        filesize = int(header[54:62], 16)
        devmajor = int(header[62:70], 16)
        devminor = int(header[70:78], 16)
        rdevmajor = int(header[78:86], 16)
        rdevminor = int(header[86:94], 16)
        namesize = int(header[94:102], 16)
        check = int(header[102:110], 16)
        
        # 文件名
        name_start = offset + 110
        name_end = name_start + namesize - 1  # 去掉末尾 \x00
        filename = cpio_data[name_start:name_end].decode('utf-8', errors='replace')
        
        # 数据开始（4字节对齐）
        data_start = align_to(offset + 110 + namesize, 4)
        data_end = data_start + filesize
        
        if filename == 'TRAILER!!!':
            break
        
        # 创建文件
        file_path = os.path.join(output_dir, filename)
        
        if mode & 0o170000 == 0o040000:  # 目录
            os.makedirs(file_path, exist_ok=True)
        elif mode & 0o170000 == 0o120000:  # 符号链接
            link_target = cpio_data[data_start:data_end].decode('utf-8', errors='replace')
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                os.symlink(link_target, file_path)
            except:
                pass
        elif mode & 0o170000 == 0o100000:  # 普通文件
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'wb') as f:
                f.write(cpio_data[data_start:data_end])
            file_count += 1
        
        # 下一个条目（4字节对齐）
        offset = align_to(data_end, 4)
    
    print(f"  CPIO 提取完成: {file_count} 个文件")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("用法: python unpack_boot.py <boot.img> <输出目录>")
        sys.exit(1)
    
    unpack_boot_image(sys.argv[1], sys.argv[2])
