import re
import sys

exe_path = r'D:\gc\MIO-KITCHEN-4.1.8-win\tool.exe'

with open(exe_path, 'rb') as f:
    data = f.read()

print(f'File size: {len(data)} bytes')

# Search for key terms in both ASCII and UTF-16LE
keywords = [
    b'xtc', b'XTC', b'decrypt', b'Decrypt', b'DECRYPT',
    b'xml', b'XML', b'aes', b'AES', b'xor', b'XOR',
    b'key', b'KEY', b'iv', b'IV', b'cipher', b'Cipher',
    b'rawprogram', b'ota.xml', b'patch0',
    b'switch', b'module', b'db',
    '小天才'.encode('utf-8'),  # UTF-8
]

# UTF-8 search
text_utf8 = data.decode('utf-8', errors='ignore')

# Search for function/class names related to xtc decrypt
patterns = [
    r'decrypt_xtc\w*',
    r'xtc\w*decrypt\w*',
    r'Xtc\w*',
    r'xtc_\w+',
    r'def\s+\w*decrypt\w*',
    r'class\s+\w*[Xx][Tt][Cc]\w*',
    r'class\s+\w*[Dd]ecrypt\w*',
    r'AES\.new',
    r'AES\.decrypt',
    r'xor\s*[\(\[]',
    r'bytes\.fromhex',
    r'binascii\.unhexlify',
    r'PKCS7',
    r'pad\(',
    r'unpad\(',
    r'mode\s*=\s*AES\.',
    r'CBC',
    r'ECB',
    r'CTR',
    r'rawprogram\d*\.xml',
    r'ota\.xml',
    r'patch\d*\.xml',
]

print('\n=== Pattern matches in UTF-8 text ===')
for pat in patterns:
    matches = re.findall(pat, text_utf8)
    if matches:
        unique = list(set(matches))[:10]
        print(f'  {pat}: {unique}')

# Search for specific key-like strings (hex, base64)
print('\n=== Potential keys/IVs (hex strings 16-64 chars) ===')
hex_patterns = re.findall(r'\b[0-9a-fA-F]{16,64}\b', text_utf8)
hex_unique = list(set(hex_patterns))
for h in hex_unique[:30]:
    # Find context
    idx = text_utf8.find(h)
    context = text_utf8[max(0,idx-40):idx+len(h)+40].replace('\n','\\n')
    print(f'  {h}  ctx: ...{context}...')

# Search for base64-like strings near decrypt
print('\n=== Base64-like strings near decrypt context ===')
for m in re.finditer(r'decrypt', text_utf8, re.IGNORECASE):
    start = max(0, m.start()-200)
    end = min(len(text_utf8), m.end()+200)
    context = text_utf8[start:end]
    # Find base64 strings
    b64 = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', context)
    if b64:
        print(f'  at pos {m.start()}: b64 candidates: {b64[:3]}')

# Look for the actual decrypt function code snippets
print('\n=== Code context around "decrypt" (first 10 occurrences) ===')
count = 0
for m in re.finditer(r'decrypt', text_utf8, re.IGNORECASE):
    if count >= 10:
        break
    start = max(0, m.start()-100)
    end = min(len(text_utf8), m.end()+100)
    context = text_utf8[start:end].replace('\n', '\\n').replace('\r', '')
    print(f'  [{count}] pos={m.start()}: ...{context}...')
    count += 1

# Search for xtc specifically
print('\n=== "xtc" occurrences ===')
for m in re.finditer(r'xtc', text_utf8, re.IGNORECASE):
    start = max(0, m.start()-80)
    end = min(len(text_utf8), m.end()+80)
    context = text_utf8[start:end].replace('\n', '\\n').replace('\r', '')
    print(f'  pos={m.start()}: ...{context}...')
