import struct
import os

# 路径
author_vbmeta = r'H:\xtcz10check\2\250803\vbmeta.img'
v101_abl = r'H:\xtcz10check\v1.0.1_dump\abl_v101.img'
results = []

# ========== 1. 从作者 vbmeta 提取公钥 ==========
results.append('=' * 60)
results.append('作者 vbmeta.img 中的公钥')
results.append('=' * 60)

f = open(author_vbmeta, 'rb')
vbmeta_data = f.read()
f.close()

# AVB 镜像结构（大端序）
# 0x00: magic (4) = "AVB0"
# 0x04: required_libavb_version_major (4)
# 0x08: required_libavb_version_minor (4)
# 0x0C: authentication_data_block_size (8)
# 0x14: auxiliary_data_block_size (8)
# 0x1C: algorithm_type (4)
# 0x20: hash_offset (8)
# 0x28: hash_size (8)
# 0x30: signature_offset (8)
# 0x38: signature_size (8)
# 0x40: public_key_offset (8)
# 0x48: public_key_size (8)
# 0x50: public_key_metadata_offset (8)
# 0x58: public_key_metadata_size (8)
# 0x60: descriptors_offset (8)
# 0x68: descriptors_size (8)
# 0x70: rollback_index (8)
# 0x78: flags (4)
# ...

magic = vbmeta_data[0:4]
results.append(f'  magic: {magic}')
auth_block_size = struct.unpack_from('>Q', vbmeta_data, 0x0C)[0]
aux_block_size = struct.unpack_from('>Q', vbmeta_data, 0x14)[0]
algorithm_type = struct.unpack_from('>I', vbmeta_data, 0x1C)[0]
results.append(f'  algorithm_type: {algorithm_type} (2=SHA256_RSA4096)')
results.append(f'  auth_block_size: {auth_block_size}')
results.append(f'  aux_block_size: {aux_block_size}')

pubkey_offset = struct.unpack_from('>Q', vbmeta_data, 0x40)[0]
pubkey_size = struct.unpack_from('>Q', vbmeta_data, 0x48)[0]
results.append(f'  public_key_offset: {pubkey_offset} (0x{pubkey_offset:X})')
results.append(f'  public_key_size: {pubkey_size}')

# 注意：public_key_offset 是相对于 authentication data block 起始的偏移
# authentication data block 从镜像偏移 256 (0x100) 开始
# 但实际上 AVB 镜像中，offset 是相对于镜像开头的？需要确认
# 根据 libavb 代码，public_key_offset 是相对于镜像起始的绝对偏移
# 不对，让我重新看。实际上 AVB 镜像布局是：
# [AvbVBMetaImageHeader (256 bytes)] [authentication data] [auxiliary data] [descriptors]
# hash_offset, signature_offset, public_key_offset 都是相对于镜像起始的绝对偏移

pubkey_abs = pubkey_offset
pubkey_data = vbmeta_data[pubkey_abs:pubkey_abs+pubkey_size]
results.append(f'  公钥前64字节: {pubkey_data[:64].hex()}')
results.append(f'  公钥SHA256: {__import__("hashlib").sha256(pubkey_data).hexdigest()}')

# RSA4096 公钥的 ASN.1 格式：
# SEQUENCE {
#   SEQUENCE {
#     OID 1.2.840.113549.1.1.1 (rsaEncryption)
#     NULL
#   }
#   BIT STRING {
#     SEQUENCE {
#       INTEGER (modulus, 512字节)
#       INTEGER (exponent, 通常65537)
#     }
#   }
# }
# 总大小通常是 1032 字节左右（RSA4096）

# 提取 modulus（RSA 公钥的核心，用于对比）
# 先找 ASN.1 结构
results.append(f'\n  公钥完整内容（{pubkey_size}字节）:')
for i in range(0, min(pubkey_size, 128), 16):
    hex_part = ' '.join(f'{b:02X}' for b in pubkey_data[i:i+16])
    results.append(f'    {i:04X}: {hex_part}')

# ========== 2. 从 abl 证书链提取 "General Use XTC Key 1" 公钥 ==========
results.append('\n' + '=' * 60)
results.append('abl 中 "General Use XTC Key 1" 证书的公钥')
results.append('=' * 60)

f = open(v101_abl, 'rb')
abl_data = f.read()
f.close()

# 搜索 "General Use XTC Key 1" 字符串
target = b'General Use XTC Key 1'
pos = abl_data.find(target)
results.append(f'  "General Use XTC Key 1" 找到 @0x{pos:X}')

# X.509 证书结构中，subject 后面是 subjectPublicKeyInfo
# 证书大致结构：
# Certificate ::= SEQUENCE {
#   tbsCertificate TBSCertificate,
#   signatureAlgorithm AlgorithmIdentifier,
#   signatureValue BIT STRING
# }
# TBSCertificate ::= SEQUENCE {
#   version [0] EXPLICIT Version DEFAULT v1,
#   serialNumber CertificateSerialNumber,
#   signature AlgorithmIdentifier,
#   issuer Name,
#   validity Validity,
#   subject Name,
#   subjectPublicKeyInfo SubjectPublicKeyInfo,  ← 我们要这个
#   ...
# }
# SubjectPublicKeyInfo ::= SEQUENCE {
#   algorithm AlgorithmIdentifier,
#   subjectPublicKey BIT STRING
# }

# 在证书中，subject 名称（含 "General Use XTC Key 1"）后面紧跟着 subjectPublicKeyInfo
# 我们需要从 subject 名称之后解析 ASN.1 找到公钥

# 简单方法：搜索 subject 名称后面的 SEQUENCE（公钥信息）
# "General Use XTC Key 1" 在 UTF8String 中，后面是 subjectPublicKeyInfo 的 SEQUENCE

# 先找到包含这个字符串的证书的起始位置
# 证书以 0x30 0x82 开头（SEQUENCE，长格式长度）
# 往前找最近的 0x30 0x82

cert_start = -1
for i in range(pos, max(0, pos-0x1000), -1):
    if abl_data[i] == 0x30 and abl_data[i+1] == 0x82:
        cert_start = i
        break
results.append(f'  证书起始位置推测: 0x{cert_start:X}')

# 从证书起始位置解析，找到 subjectPublicKeyInfo
# 简单粗暴：在 "General Use XTC Key 1" 之后搜索 RSA 公钥的 OID
# rsaEncryption OID = 06 09 2A 86 48 86 F7 0D 01 01 01
rsa_oid = b'\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01'
oid_pos = abl_data.find(rsa_oid, pos)
results.append(f'  RSA OID 找到 @0x{oid_pos:X} (在subject名称之后)')

# subjectPublicKeyInfo 的结构：
# 30 82 XX XX        SEQUENCE (SubjectPublicKeyInfo)
#   30 0D             SEQUENCE (AlgorithmIdentifier)
#     06 09 2A 86...  OID (rsaEncryption)
#     05 00             NULL
#   03 82 XX XX 00     BIT STRING (公钥数据，开头00表示未用位数)
#     30 82 XX XX       SEQUENCE (RSAPublicKey)
#       02 82 02 01     INTEGER (modulus, 513字节含前导0)
#         ... modulus ...
#       02 03             INTEGER (exponent, 3字节)
#         01 00 01         (65537)

# 从 RSA OID 位置往前找 SubjectPublicKeyInfo 的 SEQUENCE (0x30 0x82)
spki_start = -1
for i in range(oid_pos, max(0, oid_pos-32), -1):
    if abl_data[i] == 0x30 and abl_data[i+1] == 0x82:
        spki_start = i
        break
results.append(f'  SubjectPublicKeyInfo 起始 @0x{spki_start:X}')

# 提取整个 SubjectPublicKeyInfo
if spki_start >= 0:
    spki_len = struct.unpack_from('>H', abl_data, spki_start+2)[0]
    spki_total = 4 + spki_len  # 2字节标签 + 2字节长度 + 内容
    spki_data = abl_data[spki_start:spki_start+spki_total]
    results.append(f'  SubjectPublicKeyInfo 大小: {spki_total} 字节')
    results.append(f'  SPKI 前64字节: {spki_data[:64].hex()}')
    results.append(f'  SPKI SHA256: {__import__("hashlib").sha256(spki_data).hexdigest()}')

    # 提取 modulus（RSA公钥核心）
    # 在 SPKI 中找 BIT STRING (03 82) 然后里面的 SEQUENCE (30 82) 然后 INTEGER (02 82 02 01)
    bit_string_pos = spki_data.find(b'\x03\x82')
    if bit_string_pos >= 0:
        # BIT STRING 后面是 00（未用位数），然后是 RSAPublicKey SEQUENCE
        rsa_seq_pos = spki_data.find(b'\x30\x82', bit_string_pos)
        if rsa_seq_pos >= 0:
            # RSAPublicKey 中第一个 INTEGER 是 modulus
            int_pos = spki_data.find(b'\x02\x82\x02\x01', rsa_seq_pos)
            if int_pos >= 0:
                modulus_start = int_pos + 6  # 跳过 02 82 02 01 + 长度
                modulus_data = spki_data[modulus_start:modulus_start+512]
                results.append(f'\n  RSA modulus (512字节) 前64: {modulus_data[:64].hex()}')
                results.append(f'  modulus SHA256: {__import__("hashlib").sha256(modulus_data).hexdigest()}')

                # 对比作者 vbmeta 中的 modulus
                # 从 vbmeta 公钥中提取 modulus
                vb_pubkey = pubkey_data
                vb_bit_string = vb_pubkey.find(b'\x03\x82')
                if vb_bit_string >= 0:
                    vb_rsa_seq = vb_pubkey.find(b'\x30\x82', vb_bit_string)
                    if vb_rsa_seq >= 0:
                        vb_int_pos = vb_pubkey.find(b'\x02\x82\x02\x01', vb_rsa_seq)
                        if vb_int_pos >= 0:
                            vb_modulus_start = vb_int_pos + 6
                            vb_modulus = vb_pubkey[vb_modulus_start:vb_modulus_start+512]
                            results.append(f'\n  作者vbmeta modulus (512字节) 前64: {vb_modulus[:64].hex()}')
                            results.append(f'  作者vbmeta modulus SHA256: {__import__("hashlib").sha256(vb_modulus).hexdigest()}')

                            # 对比
                            if modulus_data == vb_modulus:
                                results.append(f'\n  *** 结论：abl中的"General Use XTC Key 1"公钥与作者vbmeta公钥完全一致！***')
                                results.append(f'  这意味着作者用小天才的私钥签名了vbmeta，或者abl不验证签名')
                            else:
                                results.append(f'\n  *** 结论：两个公钥不同 ***')
                                results.append(f'  作者用了自定义密钥，abl必须被patch或有其他绕过方式')

output = '\n'.join(results)
out_path = r'H:\xtcz10check\v1.0.1_dump\key_comparison.txt'
open(out_path, 'w', encoding='utf-8').write(output)
print(f'完成，结果写入 {out_path}')
