import os
import random
from Crypto.Cipher import AES

def random_key():
    """返回 16 字节随机密钥"""
    return os.urandom(16)

def random_padding_bytes():
    """返回 5~10 字节的随机前/后缀"""
    length = random.randint(5, 10)
    return os.urandom(length)

def pkcs7_pad(message: bytes, block_size: int) -> bytes:
    """简单的 PKCS#7 填充实现"""
    pad_len = block_size - (len(message) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return message + bytes([pad_len] * pad_len)

def pkcs7_unpad(message: bytes) -> bytes:
    """去填充（本题不常用到，但完整写上）"""
    pad_len = message[-1]
    return message[:-pad_len]


def encryption_oracle(key: bytes, user_message: bytes):
    """
    随机选择 ECB 或 CBC，加随机前后缀并返回 (ciphertext, mode_used)
    mode_used 使用 AES.MODE_ECB 或 AES.MODE_CBC 的常量值表示
    """
    # 随机选择模式：0 -> ECB, 1 -> CBC
    choice = random.randint(0, 1)
    if choice == 0:
        chosen_mode = AES.MODE_ECB
    else:
        chosen_mode = AES.MODE_CBC

    # 随机前后缀，并拼接
    prefix = random_padding_bytes()
    suffix = random_padding_bytes()
    plaintext = prefix + user_message + suffix

    # 填充到 16 字节的倍数
    plaintext = pkcs7_pad(plaintext, AES.block_size)

    # 根据模式分别加密（写得很展开）
    if chosen_mode == AES.MODE_ECB:
        # ECB 不需要 IV
        cipher_obj = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher_obj.encrypt(plaintext)
        # 返回密文和模式常量
        return ciphertext, AES.MODE_ECB
    else:
        # CBC 需要随机 IV
        iv = random_key()
        cipher_obj = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher_obj.encrypt(plaintext)
        return ciphertext, AES.MODE_CBC


def detect_mode_oracle(ciphertext: bytes) -> int:
    """
    通过检测重复的 16 字节块判断是否为 ECB。
    如果有重复块 -> 很可能是 ECB；否则认为是 CBC。
    这里不使用 set，而用最简单的两重循环（更“笨”也更好理解）。
    返回 AES.MODE_ECB 或 AES.MODE_CBC
    """
    block_size = AES.block_size
    # 切分成块（显式循环）
    blocks = []
    i = 0
    while i < len(ciphertext):
        blocks.append(ciphertext[i:i+block_size])
        i += block_size

    # 对不起我是笨蛋（）最笨的重复检测：两重循环比较每对块
    n = len(blocks)
    for i in range(n):
        for j in range(i + 1, n):
            if blocks[i] == blocks[j]:
                # 找到重复块，判断为 ECB
                return AES.MODE_ECB

    # 没有重复块，判断为 CBC
    return AES.MODE_CBC


def run_detection_test(trials: int = 1000):
    random.seed(0xC0FFEE)  # 固定随机种子，便于复现（可删喵）
    key = random_key()
    # 构造一个容易在 ECB 中产生重复块的消息：全 0，长度 3 块
    message = b"\x00" * (16 * 3)

    correct = 0
    for t in range(trials):
        ciphertext, real_mode = encryption_oracle(key, message)
        guessed_mode = detect_mode_oracle(ciphertext)
        if guessed_mode == real_mode:
            correct += 1

        # 可选喵：打印前几个试验的详细信息
        if t < 5:
            print(f"Trial {t+1}: real_mode = { 'ECB' if real_mode==AES.MODE_ECB else 'CBC' }, guessed = { 'ECB' if guessed_mode==AES.MODE_ECB else 'CBC' }")

    accuracy = correct / trials
    print(f"Accuracy over {trials} trials: {accuracy:.2%}")

if __name__ == "__main__":
    run_detection_test(1000)