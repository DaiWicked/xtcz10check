import struct

def hexdump(data, length=256):
    for i in range(0, min(length, len(data)), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        print(f'{i:08x}: {hex_part:<48} {ascii_part}')

files = [
    ("作者 vbmeta.img", r"H:\xtcz10check\AllToolBox1.4.6\bin\EDL\rooting\vbmeta.img"),
    ("作者 vbmeta_system.img", r"H:\xtcz10check\AllToolBox1.4.6\bin\EDL\rooting\vbmeta_system.img"),
    ("原版 281/vbmeta.img", r"H:\xtcz10check\AllToolBox1.4.6\bin\EDL\rooting\281\vbmeta.img"),
    ("原版 281/vbmeta_system.img", r"H:\xtcz10check\AllToolBox1.4.6\bin\EDL\rooting\281\vbmeta_system.img"),
]

for name, path in files:
    print(f"\n{'='*70}")
    print(f"{name}")
    print(f"{'='*70}")
    with open(path, 'rb') as f:
        data = f.read()
    print(f"大小: {len(data)} 字节")
    hexdump(data, 256)

    # 搜索 AVB0
    pos = data.find(b'AVB0')
    if pos >= 0:
        print(f"\nAVB0  found at offset {pos}")
    else:
        print("\nAVB0 not found")

    # 搜索其他魔数
    for magic in [b'AVB0', b'ANDROID!', b'VBMeta', b'\x9a\xb4\x01=']:
        p = data.find(magic)
        if p >= 0:
            print(f"  {magic.hex()} found at offset {p}")
