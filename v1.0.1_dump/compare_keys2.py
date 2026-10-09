import struct
import hashlib

author_vbmeta = r'H:\xtcz10check\2\250803\vbmeta.img'
v101_abl = r'H:\xtcz10check\v1.0.1_dump\abl_v101.img'
results = []

f = open(author_vbmeta, 'rb')
vb = f.read()
f.close()

# AVB header 字段（大端序）
pubkey_offset_rel = struct.unpack_from('>Q', vb, 0x40)[0]
pubkey_size = struct.unpack_from('>Q', vb, 0x48)[0]
results.append(f'vbmeta public_key_offset(relative)={pubkey_offset_rel}, size={pubkey_size}')

# 尝试两种偏移解释
for label, abs_off in [('绝对偏移', pubkey_offset_rel), ('auth_block起始+256', 256 + pubkey_offset_rel)]:
    if abs_off + pubkey_size <= len(vb):
        data = vb[abs_off:abs_off+pubkey_size]
        starts_with_3082 = data[:2] == b'\x30\x82'
        results.append(f'  {label} @0x{abs_off:X}: 前4字节={data[:4].hex()}, 以3082开头={starts_with_3082}')
        if starts_with_3082:
            results.append(f'  *** 正确偏移是: {label} ***')
            # 提取 RSA modulus
            # 30 82 XX XX (SPKI) -> 30 0D (algoid) -> 03 82 XX XX 00 (bitstring) -> 30 82 XX XX (RSAPubKey) -> 02 82 02 01 (modulus INTEGER)
            bit_pos = data.find(b'\x03\x82')
            if bit_pos >= 0:
                rsa_seq = data.find(b'\x30\x82', bit_pos)
                if rsa_seq >= 0:
                    int_pos = data.find(b'\x02\x82\x02\x01', rsa_seq)
                    if int_pos >= 0:
                        mod_start = int_pos + 6
                        vb_modulus = data[mod_start:mod_start+512]
                        results.append(f'  作者vbmeta modulus SHA256: {hashlib.sha256(vb_modulus).hexdigest()}')
                        results.append(f'  作者vbmeta modulus 前32: {vb_modulus[:32].hex()}')

# 从 abl 提取 "General Use XTC Key 1" 证书的公钥
f = open(v101_abl, 'rb')
abl = f.read()
f.close()

# 搜索所有 RSA4096 公钥的 modulus（02 82 02 01 开头，后面512字节modulus）
# 在证书区域 0x25000-0x26060 搜索
results.append('\n=== abl 证书区域中的 RSA 公钥 ===')
cert_region = abl[0x25000:0x26060]
modulus_positions = []
pos = 0
while True:
    idx = cert_region.find(b'\x02\x82\x02\x01', pos)
    if idx < 0:
        break
    mod_start = idx + 6
    if mod_start + 512 <= len(cert_region):
        modulus = cert_region[mod_start:mod_start+512]
        abs_pos = 0x25000 + mod_start
        modulus_positions.append((abs_pos, modulus))
        results.append(f'  找到 modulus @0x{abs_pos:X}, SHA256: {hashlib.sha256(modulus).hexdigest()}')
    pos = idx + 1

# 对比
results.append('\n=== 公钥对比结论 ===')
if 'vb_modulus' in dir():
    for abs_pos, mod in modulus_positions:
        if mod == vb_modulus:
            results.append(f'  *** 匹配！abl @0x{abs_pos:X} 的公钥与作者vbmeta公钥完全相同 ***')
            results.append(f'  这意味着：作者用小天才"General Use XTC Key"的私钥签名了vbmeta')
            results.append(f'  或者：abl不验证vbmeta签名，作者只是随便用了一个密钥')
        else:
            results.append(f'  abl @0x{abs_pos:X} 与作者vbmeta公钥不同')

# 额外：检查作者vbmeta的签名是否有效（用公钥验证签名）
# 这比较复杂，先跳过。但我们可以检查签名是否全零或假签名
sig_offset_rel = struct.unpack_from('>Q', vb, 0x30)[0]
sig_size = struct.unpack_from('>Q', vb, 0x38)[0]
sig_abs = 256 + sig_offset_rel
sig_data = vb[sig_abs:sig_abs+sig_size]
results.append(f'\n=== 作者vbmeta签名检查 ===')
results.append(f'  signature_offset={sig_offset_rel}, size={sig_size}, abs=0x{sig_abs:X}')
results.append(f'  签名前32字节: {sig_data[:32].hex()}')
all_zero = all(b == 0 for b in sig_data)
results.append(f'  签名全零: {all_zero}')
if not all_zero:
    results.append(f'  签名非零，看起来是真实的RSA4096签名（512字节）')

output = '\n'.join(results)
out_path = r'H:\xtcz10check\v1.0.1_dump\key_comparison2.txt'
open(out_path, 'w', encoding='utf-8').write(output)
print(f'完成，结果写入 {out_path}')
print(f'找到 {len(modulus_positions)} 个RSA modulus')
