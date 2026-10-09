import hashlib

author_vbmeta = r'H:\xtcz10check\2\250803\vbmeta.img'
v101_abl = r'H:\xtcz10check\v1.0.1_dump\abl_v101.img'
results = []

def find_rsa_public_keys(data, name):
    """在二进制数据中搜索 RSA 公钥，通过 rsaEncryption OID 定位"""
    rsa_oid = b'\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01'
    keys = []
    pos = 0
    while True:
        idx = data.find(rsa_oid, pos)
        if idx < 0:
            break
        # rsaEncryption OID 在 AlgorithmIdentifier 中
        # 结构: 30 0D (AlgorithmIdentifier SEQUENCE)
        #        06 09 2A 86 48 86 F7 0D 01 01 01 (OID)
        #        05 00 (NULL)
        # 后面是 BIT STRING (03 82 XX XX 00) 包含 RSAPublicKey
        # 找 BIT STRING
        bit_pos = data.find(b'\x03\x82', idx)
        if bit_pos >= 0 and bit_pos - idx < 32:
            # BIT STRING 后面1字节是未用位数(00)，然后是 RSAPublicKey SEQUENCE
            rsa_seq_pos = data.find(b'\x30\x82', bit_pos + 4)
            if rsa_seq_pos >= 0 and rsa_seq_pos - bit_pos < 8:
                # RSAPublicKey: SEQUENCE { INTEGER modulus, INTEGER exponent }
                # modulus 是 02 82 02 00/01 (512或513字节)
                for mod_pattern in [b'\x02\x82\x02\x01', b'\x02\x82\x02\x00']:
                    int_pos = data.find(mod_pattern, rsa_seq_pos)
                    if int_pos >= 0 and int_pos - rsa_seq_pos < 8:
                        if mod_pattern == b'\x02\x82\x02\x01':
                            mod_start = int_pos + 6
                            mod_len = 512
                        else:
                            mod_start = int_pos + 4
                            mod_len = 512
                        modulus = data[mod_start:mod_start+mod_len]
                        if modulus[0] == 0:
                            modulus = modulus[1:]
                        # 找 exponent (通常 02 03 01 00 01 = 65537)
                        exp_pos = data.find(b'\x02\x03\x01\x00\x01', mod_start)
                        exp = 65537
                        if exp_pos < 0:
                            exp_pos = data.find(b'\x02\x03', mod_start+mod_len)
                            if exp_pos >= 0:
                                exp = int.from_bytes(data[exp_pos+2:exp_pos+5], 'big')
                        keys.append({
                            'oid_pos': idx,
                            'modulus': modulus,
                            'exponent': exp,
                            'mod_sha256': hashlib.sha256(modulus).hexdigest(),
                        })
                        break
        pos = idx + 1
    return keys

# 搜索作者 vbmeta 中的公钥
f = open(author_vbmeta, 'rb')
vb = f.read()
f.close()
results.append('=== 作者 vbmeta 中的 RSA 公钥 ===')
vb_keys = find_rsa_public_keys(vb, 'vbmeta')
results.append(f'找到 {len(vb_keys)} 个公钥')
for i, k in enumerate(vb_keys):
    results.append(f'  [{i}] OID@0x{k["oid_pos"]:X}, exponent={k["exponent"]}')
    results.append(f'      modulus SHA256: {k["mod_sha256"]}')
    results.append(f'      modulus 前32: {k["modulus"][:32].hex()}')

# 搜索 abl 中的公钥
f = open(v101_abl, 'rb')
abl = f.read()
f.close()
results.append('\n=== abl 中的 RSA 公钥 ===')
abl_keys = find_rsa_public_keys(abl, 'abl')
results.append(f'找到 {len(abl_keys)} 个公钥')
for i, k in enumerate(abl_keys):
    results.append(f'  [{i}] OID@0x{k["oid_pos"]:X}, exponent={k["exponent"]}')
    results.append(f'      modulus SHA256: {k["mod_sha256"]}')
    results.append(f'      modulus 前32: {k["modulus"][:32].hex()}')

# 对比
results.append('\n=== 公钥对比结论 ===')
if vb_keys and abl_keys:
    for i, vk in enumerate(vb_keys):
        for j, ak in enumerate(abl_keys):
            if vk['modulus'] == ak['modulus']:
                results.append(f'  *** 匹配！作者vbmeta公钥[{i}] == abl公钥[{j}] ***')
                results.append(f'  这意味着作者用了和abl相同的密钥签名vbmeta')
                results.append(f'  可能：1)作者持有小天才私钥 2)abl不验证签名 3)密钥是通用测试密钥')
            else:
                results.append(f'  作者vbmeta[{i}] != abl[{j}] (modulus不同)')

# 额外：检查vbmeta中是否有 "General Use XTC Key" 相关字符串
results.append('\n=== vbmeta 中的字符串搜索 ===')
for keyword in [b'XTC', b'General Use', b'xtc', b'imoo', b'careme']:
    pos = vb.find(keyword)
    if pos >= 0:
        results.append(f'  找到 "{keyword.decode()}" @0x{pos:X}')
    else:
        results.append(f'  未找到 "{keyword.decode()}"')

output = '\n'.join(results)
out_path = r'H:\xtcz10check\v1.0.1_dump\final_key_comparison.txt'
open(out_path, 'w', encoding='utf-8').write(output)
print(f'完成，结果写入 {out_path}')
print(f'vbmeta公钥数: {len(vb_keys)}, abl公钥数: {len(abl_keys)}')
