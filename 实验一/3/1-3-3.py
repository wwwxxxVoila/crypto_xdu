from Crypto.Cipher import AES
import base64

# 7.ECB 模式下的 AES
def decrypt_aes_ecb(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def pkcs7_unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

# 主程序
if __name__ == "__main__":
    # 读取并解码base64
    with open('file-7.txt', 'r') as f:
        encoded_data = f.read().strip()
    # 解码base64得到密文
    ciphertext = base64.b64decode(encoded_data)
    # 密钥
    key = b"YELLOW SUBMARINE"
    # 解密
    decrypted_data = decrypt_aes_ecb(ciphertext, key)

    # 移除填充并解码为文本
    try:
        # 尝试移除PKCS7填充
        plaintext = pkcs7_unpad(decrypted_data)
        result = plaintext.decode('utf-8')
    except:
        # 如果移除填充失败，直接解码
        result = decrypted_data.decode('utf-8', errors='ignore')

    print("解密后的内容:")
    print(result)


# 8.检测 ECB 模式下的 AES
def detect_ecb_simple(hex_strings):
    """简单检测ECB模式"""
    for i, hex_str in enumerate(hex_strings, 1):
        ciphertext = bytes.fromhex(hex_str)
        block_size = 16
        blocks = [ciphertext[j:j + block_size] for j in range(0, len(ciphertext), block_size)]

        if len(blocks) != len(set(blocks)):
            return i, hex_str

    return None, None

# 主程序
with open('file-8.txt', 'r') as f:
    hex_strings = [line.strip() for line in f if line.strip()]

line_num, ecb_ciphertext = detect_ecb_simple(hex_strings)

if ecb_ciphertext:
    print(f"检测到ECB模式加密的密文在行号: {line_num}")
    print(f"密文: {ecb_ciphertext}")
else:
    print("未检测到ECB模式加密的密文")
