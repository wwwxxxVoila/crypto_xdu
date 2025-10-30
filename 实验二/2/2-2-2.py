from Crypto.Cipher import AES
from base64 import b64decode

#PKCS#7 填充与去除
def pad(msg: bytes, block_size: int) -> bytes:
    # 算出要补几个字节
    pad_len = block_size - (len(msg) % block_size)
    # 补 pad_len 个同样值的字节
    return msg + bytes([pad_len] * pad_len)

def unpad(msg: bytes) -> bytes:
    # 最后一个字节的值就是补了多少个
    pad_len = msg[-1]
    return msg[:-pad_len]


# AES ECB 模式
def ecb_encrypt_one_block(block: bytes, key: bytes) -> bytes:
    # 只加密一块（16字节）
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)

def ecb_decrypt_one_block(block: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(block)


# 异或喵
def xor_bytes(a: bytes, b: bytes) -> bytes:
    # zip 会一对一配好，x ^ y 是异或
    return bytes([x ^ y for x, y in zip(a, b)])


# CBC模式加密
def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    # 先填充
    plaintext = pad(plaintext, AES.block_size)
    
    ciphertext = b''
    prev_block = iv

    # 一块一块加密
    for i in range(0, len(plaintext), AES.block_size):
        block = plaintext[i:i+AES.block_size]
        
        #明文块与上一个密文块异或
        xored = xor_bytes(block, prev_block)
        
        #再用AES-ECB加密
        encrypted = ecb_encrypt_one_block(xored, key)
        
        #把这块密文拼起来
        ciphertext += encrypted
        prev_block = encrypted

    return ciphertext


#CBC模式解密
def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    plaintext = b''
    prev_block = iv

    for i in range(0, len(ciphertext), AES.block_size):
        block = ciphertext[i:i+AES.block_size]
        
        #先用AES-ECB解密
        decrypted = ecb_decrypt_one_block(block, key)
        
        #与上一个密文块异或
        real_plain = xor_bytes(decrypted, prev_block)
        
        plaintext += real_plain
        prev_block = block

    # 去掉padding
    return unpad(plaintext)


# main喵
if __name__ == '__main__':
    iv = b'\x00' * AES.block_size
    key = b'YELLOW SUBMARINE'
    
    with open('10.txt', 'r') as f:
        data = f.read()
    
    ciphertext = b64decode(data)

    result = cbc_decrypt(ciphertext, key, iv)
    print(result.decode().rstrip())