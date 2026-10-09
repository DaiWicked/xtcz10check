import os

devinfo_path = r"H:\xtcz10check\tools\devinfo_after_test1.bin"
if not os.path.exists(devinfo_path):
    # Try other locations
    import glob
    for f in glob.glob(r"H:\xtcz10check\**\devinfo_after*", recursive=True):
        print(f"Found: {f}")
        devinfo_path = f
        break

if os.path.exists(devinfo_path):
    with open(devinfo_path, "rb") as f:
        data = f.read()
    print(f"File: {devinfo_path}")
    print(f"Size: {len(data)} bytes (0x{len(data):X})")
    
    print(f"\n=== First 0x100 bytes ===")
    for i in range(0, min(0x100, len(data)), 16):
        hex_str = " ".join(f"{b:02X}" for b in data[i:i+16])
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data[i:i+16])
        print(f"  {i:04X}: {hex_str:<48} {ascii_str}")
    
    print(f"\n=== Key fields ===")
    print(f"  Magic @0x00: {data[0:13]}")
    print(f"  Magic match: {data[0:13] == b'ANDROID-BOOT!'}")
    print(f"  is_unlocked @0x0D: 0x{data[0x0D]:02X} ({data[0x0D]})")
    print(f"  is_unlock_critical @0x0E: 0x{data[0x0E]:02X} ({data[0x0E]})")
    print(f"  charger_screen @0x0F: 0x{data[0x0F]:02X}")
    print(f"  init_flag @0x90: 0x{data[0x90]:02X}")
    
    # Find non-zero regions
    print(f"\n=== Non-zero regions ===")
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
    
    # Compare with original
    orig_path = r"H:\xtcz10check\v1.0.1_dump\devinfo.img"
    if os.path.exists(orig_path):
        with open(orig_path, "rb") as f:
            orig = f.read()
        print(f"\n=== Compare with original ===")
        diffs = []
        for i in range(min(len(data), len(orig))):
            if data[i] != orig[i]:
                diffs.append((i, orig[i], data[i]))
        print(f"  Differences: {len(diffs)} bytes")
        if diffs:
            print(f"  First 20 differences:")
            for i, (off, old, new) in enumerate(diffs[:20]):
                print(f"    0x{off:04X}: 0x{old:02X} -> 0x{new:02X}")
else:
    print("File not found!")
