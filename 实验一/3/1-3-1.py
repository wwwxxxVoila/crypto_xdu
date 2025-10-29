import base64

 # 1.十六进制转 Base64
def hex_to_base64(hex_string):
    # 将十六进制字符串转换为字节
    raw_bytes = bytes.fromhex(hex_string)
    # 将字节编码为base64
    base64_encoded = base64.b64encode(raw_bytes)
    # 返回base64字符串（解码为普通字符串）
    return base64_encoded.decode('ascii')

hex_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
result = hex_to_base64(hex_input)
print(f"输出: {result}")

# 2.固定异或
def fixed_xor(hex1, hex2):
    # 将十六进制字符串转换为字节
    bytes1 = bytes.fromhex(hex1)
    bytes2 = bytes.fromhex(hex2)

    # 检查长度是否相等
    if len(bytes1) != len(bytes2):
        raise ValueError("输入字符串长度必须相等")

    # 执行XOR操作
    result_bytes = bytes(a ^ b for a, b in zip(bytes1, bytes2))

    # 将结果转换回十六进制字符串
    return result_bytes.hex()

# 测试
hex1 = "1c0111001f010100061a024b53535009181c"
hex2 = "686974207468652062756c6c277320657965"

# 执行XOR操作
result = fixed_xor(hex1, hex2)

print(f"输入1: {hex1}")
print(f"输入2: {hex2}")
print(f"结果:  {result}")

# 3.单字节异或密码
def single_byte_xor(ciphertext_hex, key):
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    return bytes([b ^ key for b in ciphertext_bytes])

def english_score(text_bytes):
    # 常见英文字母频率（近似值）
    freq = {
        b' ': 15, b'e': 13, b't': 12, b'a': 8, b'o': 8, b'i': 7, b'n': 7,
        b's': 6, b'h': 6, b'r': 6, b'd': 4, b'l': 4, b'c': 3, b'u': 3,
        b'm': 2, b'w': 2, b'f': 2, b'g': 2, b'y': 2, b'p': 2, b'b': 1,
        b'v': 1, b'k': 1, b'j': 1, b'x': 0, b'q': 0, b'z': 0
    }

    score = 0
    for byte in text_bytes:
        # 转换为小写进行评分
        char = bytes([byte]).lower()
        if char in freq:
            score += freq[char]
        elif 32 <= byte <= 126:  # 可打印ASCII字符
            score += 0.5
        else:  # 非可打印字符，严重扣分
            score -= 10

    return score

def break_single_byte_xor(ciphertext_hex):
    best_score = float('-inf')
    best_key = None
    best_plaintext = None
    # 尝试所有可能的单字节密钥 (0-255)
    for key in range(256):
        try:
            plaintext = single_byte_xor(ciphertext_hex, key)
            score = english_score(plaintext)

            if score > best_score:
                best_score = score
                best_key = key
                best_plaintext = plaintext
        except:
            continue

    return best_key, best_plaintext, best_score

# 测试
ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
key, plaintext, score = break_single_byte_xor(ciphertext)
print(f"最佳密钥: {key} (ASCII: '{chr(key) if 32 <= key <= 126 else 'non-printable'}')")
print(f"解密文本: {plaintext.decode('ascii', errors='replace')}")
print(f"评分: {score}")

# 4.检测单字符异或
def detect_single_char_xor(hex_strings):
    def score_text(text):
        # 常见英文字母频率
        freq = {
            'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253,
            'e': 0.12702, 'f': 0.02228, 'g': 0.02015, 'h': 0.06094,
            'i': 0.06966, 'j': 0.00153, 'k': 0.00772, 'l': 0.04025,
            'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 'p': 0.01929,
            'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
            'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150,
            'y': 0.01974, 'z': 0.00074, ' ': 0.13000
        }

        score = 0
        for char in text.lower():
            if char in freq:
                score += freq[char]
        return score

    def single_char_xor_decrypt(hex_string, key):
        """使用单字符密钥解密XOR加密的十六进制字符串"""
        bytes_data = bytes.fromhex(hex_string)
        result = bytes([b ^ key for b in bytes_data])
        return result

    best_score = -1
    best_result = None
    best_string = None
    best_key = None

    for hex_string in hex_strings:
        # 尝试所有可能的单字节密钥
        for key in range(256):
            try:
                decrypted = single_char_xor_decrypt(hex_string, key)
                text = decrypted.decode('ascii', errors='ignore')
                # 计算得分
                current_score = score_text(text)

                if current_score > best_score:
                    best_score = current_score
                    best_result = text
                    best_string = hex_string
                    best_key = key
            except:
                continue

    return best_string, best_result, best_key, best_score

# 读取文件内容
with open('file-4.txt', 'r') as f:
    content = f.read().strip()

# 将内容分割成60个字符的字符串
hex_strings = [line.strip() for line in content.split('\n')]

# 检测单字符XOR
encrypted_string, decrypted_text, key, score = detect_single_char_xor(hex_strings)

print(f"使用的密钥: {key} (字符: '{chr(key) if 32 <= key <= 126 else 'non-printable'}')")
