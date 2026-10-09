import os

devinfo_path = r"H:\xtcz10check\v1.0.1_dump\devinfo.img"
if os.path.exists(devinfo_path):
    with open(devinfo_path, "rb") as f:
        data = f.read()
    print(f"File size: {len(data)} bytes (0x{len(data):X})")
    print(f"\nFirst 0x100 bytes:")
    for i in range(0, min(0x100, len(data)), 16):
        hex_str = " ".join(f"{b:02X}" for b in data[i:i+16])
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data[i:i+16])
        print(f"  {i:04X}: {hex_str:<48} {ascii_str}")
    
    # Find non-zero regions
    print(f"\nNon-zero regions:")
    in_zero = True
    start = 0
    for i in range(len(data)):
        if data[i] != 0 and in_zero:
            start = i
            in_zero = False
        elif data[i] == 0 and not in_zero:
            print(f"  0x{start:04X} - 0x{i-1:04X} ({i-start} bytes)")
            in_zero = True
    if not in_zero:
        print(f"  0x{start:04X} - 0x{len(data)-1:04X} ({len(data)-start} bytes)")
    
    # Check 0x9A0 - 0xA4F
    print(f"\n0x9A0 - 0xA4F (tail region):")
    for i in range(0x9A0, min(0xA50, len(data)), 16):
        hex_str = " ".join(f"{b:02X}" for b in data[i:i+16])
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data[i:i+16])
        print(f"  {i:04X}: {hex_str:<48} {ascii_str}")
else:
    print(f"File not found: {devinfo_path}")
    # Search for devinfo files
    import glob
    for f in glob.glob(r"H:\xtcz10check\**\devinfo*", recursive=True):
        print(f"  Found: {f}")
