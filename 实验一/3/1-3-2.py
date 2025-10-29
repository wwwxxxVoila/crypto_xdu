import base64
from itertools import combinations

# 5.实现重复密钥异或
def repeating_key_xor(plaintext, key):
    # 将文本和密钥转换为字节
    plaintext_bytes = plaintext.encode()
    key_bytes = key.encode()
    # 执行重复密钥XOR
    encrypted_bytes = bytes([
        plaintext_bytes[i] ^ key_bytes[i % len(key_bytes)]
        for i in range(len(plaintext_bytes))
    ])
    # 返回十六进制字符串
    return encrypted_bytes.hex()

# 测试数据
plaintext = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
key = "ICE"
# 加密
result = repeating_key_xor(plaintext, key)
print(f"\n加密结果: {result}")

# 6.破解重复密钥异或
# 计算汉明距离
def hamming_distance(s1, s2):
    return sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(s1, s2))

# 计算平均标准化汉明距离
def avg_normalized_hamming(ciphertext, keysize, num_blocks=4):
    blocks = [ciphertext[i * keysize:(i + 1) * keysize] for i in range(num_blocks)]
    total_distance = 0
    count = 0

    for a, b in combinations(blocks, 2):
        if len(a) == len(b):
            total_distance += hamming_distance(a, b) / len(a)
            count += 1

    return total_distance / count if count > 0 else float('inf')

# 频率分析得分
def frequency_score(text):
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    common_chars = b'etaoin shrdlu'
    score = sum(freq.get(char, 0) for char in common_chars)
    return score

# 单字节XOR破解
def single_byte_xor(ciphertext):
    best_score = 0
    best_key = 0
    best_plaintext = b''

    for key in range(256):
        plaintext = bytes([b ^ key for b in ciphertext])
        score = frequency_score(plaintext)

        if score > best_score:
            best_score = score
            best_key = key
            best_plaintext = plaintext

    return best_key, best_plaintext

# 主解密函数
def break_repeating_key_xor(ciphertext):
    # 步骤1: 找到最可能的密钥长度
    best_keysize = 2
    best_score = float('inf')

    for keysize in range(2, 41):
        score = avg_normalized_hamming(ciphertext, keysize)
        if score < best_score:
            best_score = score
            best_keysize = keysize

    print(f"最可能的密钥长度: {best_keysize}")

    # 步骤2: 分块并转置
    blocks = [ciphertext[i:i + best_keysize] for i in range(0, len(ciphertext), best_keysize)]
    transposed = []

    for i in range(best_keysize):
        block = bytes([block[i] for block in blocks if len(block) > i])
        transposed.append(block)

    # 步骤3: 对每个转置块进行单字节XOR破解
    key = []
    for block in transposed:
        key_byte, _ = single_byte_xor(block)
        key.append(key_byte)

    key = bytes(key)
    print(f"找到的密钥: {key}")

    # 步骤4: 使用密钥解密
    plaintext = bytes([ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext))])

    return plaintext, key

# 主程序
if __name__ == "__main__":
    # 读取并解码base64
    with open('file-6.txt', 'r') as f:
        encoded_data = f.read().strip()

    ciphertext = base64.b64decode(encoded_data)
    # 解密
    plaintext, key = break_repeating_key_xor(ciphertext)

    print("\n解密后的明文:")
    print(plaintext.decode('utf-8', errors='ignore'))
    print(f"\n使用的密钥: {key.decode('utf-8', errors='ignore')}")
