import struct
import hashlib

author_vbmeta = r'H:\xtcz10check\2\250803\vbmeta.img'
v101_abl = r'H:\xtcz10check\v1.0.1_dump\abl_v101.img'

f = open(author_vbmeta, 'rb')
vb = f.read()
f.close()

results = []
results.append(f'vbmeta 总大小: {len(vb)} (0x{len(vb):X})')
results.append(f'前256字节 (AVB Header):')
for i in range(0, 256, 16):
    hex_part = ' '.join(f'{b:02X}' for b in vb[i:i+16])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in vb[i:i+16])
    results.append(f'  {i:04X}: {hex_part:<48s} {ascii_part}')

# 解析头部（大端）
results.append('\n=== 头部字段解析（大端）===')
fields = [
    ('magic', 0, 4),
    ('req_ver_major', 4, 4),
    ('req_ver_minor', 8, 4),
    ('auth_block_size', 12, 8),
    ('aux_block_size', 20, 8),
    ('algorithm_type', 28, 4),
    ('hash_offset', 32, 8),
    ('hash_size', 40, 8),
    ('signature_offset', 48, 8),
    ('signature_size', 56, 8),
    ('public_key_offset', 64, 8),
    ('public_key_size', 72, 8),
    ('pk_metadata_offset', 80, 8),
    ('pk_metadata_size', 88, 8),
    ('descriptors_offset', 96, 8),
    ('descriptors_size', 104, 8),
    ('rollback_index', 112, 8),
    ('flags', 120, 4),
]
for name, off, size in fields:
    if size == 4:
        val = struct.unpack_from('>I', vb, off)[0]
    else:
        val = struct.unpack_from('>Q', vb, off)[0]
    results.append(f'  {name:24s} @0x{off:02X}: {val} (0x{val:X})')

# auth block 从 256 开始
auth_start = 256
auth_size = struct.unpack_from('>Q', vb, 12)[0]
aux_size = struct.unpack_from('>Q', vb, 20)[0]
results.append(f'\n=== 区域布局 ===')
results.append(f'  Header: 0x000-0x0FF (256字节)')
results.append(f'  Auth block: 0x{auth_start:X}-0x{auth_start+auth_size:X} ({auth_size}字节)')
results.append(f'  Aux block: 0x{auth_start+auth_size:X}-0x{auth_start+auth_size+aux_size:X} ({aux_size}字节)')

# 关键：offset 是相对于谁的？
# 读取 public_key_offset 和 signature_offset 的实际内容
pk_off = struct.unpack_from('>Q', vb, 64)[0]
pk_size = struct.unpack_from('>Q', vb, 72)[0]
sig_off = struct.unpack_from('>Q', vb, 48)[0]
sig_size = struct.unpack_from('>Q', vb, 56)[0]

results.append(f'\n=== 公钥数据（尝试两种偏移解释）===')
for label, abs_off in [('绝对偏移', pk_off), ('auth+256', auth_start+pk_off)]:
    if abs_off + pk_size <= len(vb):
        data = vb[abs_off:abs_off+pk_size]
        results.append(f'  {label} @0x{abs_off:X}:')
        for i in range(0, min(128, len(data)), 16):
            hex_part = ' '.join(f'{b:02X}' for b in data[i:i+16])
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
            results.append(f'    {i:04X}: {hex_part:<48s} {ascii_part}')
        # 检查是否是标准ASN.1 RSA公钥
        if data[:2] == b'\x30\x82':
            results.append(f'    *** 这是标准ASN.1 SubjectPublicKeyInfo! ***')
            # 提取 modulus
            bit_pos = data.find(b'\x03\x82')
            if bit_pos >= 0:
                rsa_seq = data.find(b'\x30\x82', bit_pos)
                if rsa_seq >= 0:
                    # 找 INTEGER (02 82)
                    int_pos = data.find(b'\x02\x82', rsa_seq)
                    if int_pos >= 0:
                        int_len = struct.unpack_from('>H', data, int_pos+2)[0]
                        mod_start = int_pos + 4
                        modulus = data[mod_start:mod_start+int_len]
                        # 去掉前导零
                        if modulus[0] == 0:
                            modulus = modulus[1:]
                        results.append(f'    RSA modulus 长度: {len(modulus)} 字节')
                        results.append(f'    modulus SHA256: {hashlib.sha256(modulus).hexdigest()}')
                        results.append(f'    modulus 前32: {modulus[:32].hex()}')

# 同样处理签名
results.append(f'\n=== 签名数据 ===')
for label, abs_off in [('绝对偏移', sig_off), ('auth+256', auth_start+sig_off)]:
    if abs_off + sig_size <= len(vb):
        data = vb[abs_off:abs_off+sig_size]
        results.append(f'  {label} @0x{abs_off:X}: 前32字节={data[:32].hex()}')

# 在 abl 中搜索 RSA modulus（更宽泛的搜索）
results.append(f'\n=== 在 abl 中搜索 RSA 公钥 ===')
f = open(v101_abl, 'rb')
abl = f.read()
f.close()

# 搜索 0x30 0x82 开头的 ASN.1 序列（可能是证书或公钥）
# 在证书区域 0x25000-0x26060
cert_area = abl[0x25000:0x26060]
seq_positions = []
for i in range(len(cert_area)-1):
    if cert_area[i] == 0x30 and cert_area[i+1] == 0x82:
        seq_len = struct.unpack_from('>H', cert_area, i+2)[0]
        if 100 < seq_len < 2000:  # 合理的证书/公钥大小
            seq_positions.append((0x25000+i, seq_len))

results.append(f'  找到 {len(seq_positions)} 个 ASN.1 SEQUENCE (0x30 0x82):')
for pos, length in seq_positions[:10]:
    data = abl[pos:pos+4+length]
    # 检查是否包含 RSA modulus (02 82 02 00 或 02 82 02 01)
    has_mod = b'\x02\x82\x02\x00' in data or b'\x02\x82\x02\x01' in data
    # 提取 modulus
    mod_data = None
    for pattern in [b'\x02\x82\x02\x01', b'\x02\x82\x02\x00']:
        mp = data.find(pattern)
        if mp >= 0:
            mod_start = mp + 6
            if pattern == b'\x02\x82\x02\x00':
                mod_start = mp + 4 + 0x200  # 长度0x200=512
                mod_data = data[mp+4:mp+4+512]
            else:
                mod_data = data[mod_start:mod_start+512]
            break
    if mod_data:
        if mod_data[0] == 0:
            mod_data = mod_data[1:]
        results.append(f'    @0x{pos:X} len={length}, has_modulus={has_mod}, mod_SHA256={hashlib.sha256(mod_data).hexdigest()}')
    else:
        results.append(f'    @0x{pos:X} len={length}, has_modulus={has_mod}')

output = '\n'.join(results)
out_path = r'H:\xtcz10check\v1.0.1_dump\vbmeta_structure.txt'
open(out_path, 'w', encoding='utf-8').write(output)
print(f'完成，结果写入 {out_path}')
