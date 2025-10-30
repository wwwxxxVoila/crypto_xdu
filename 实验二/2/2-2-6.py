import os
import base64
import random
from Crypto.Cipher import AES
import string

# -------------------------
# 全局随机参数（只生成一次）
# -------------------------
BLOCK_SIZE = 16
GLOBAL_KEY = os.urandom(BLOCK_SIZE)        # **固定**密钥，只生成一次
PREFIX = os.urandom(random.randint(0, 64))  # 随机前缀，只生成一次

# 隐藏的目标（和你原脚本里的相同）
SECRET = base64.b64decode(
    b"""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK"""
)

# -------------------------
# 工具：PKCS#7 填充
# -------------------------
def pkcs7_pad(b: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(b) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return b + bytes([pad_len] * pad_len)

def pkcs7_unpad(b: bytes) -> bytes:
    pad_len = b[-1]
    return b[:-pad_len]

# -------------------------
# Oracle：固定 key、固定 prefix
# -------------------------
def encryption_oracle(control_text: bytes) -> bytes:
    """
    ECB oracle with a fixed random prefix and fixed secret suffix.
    Returns AES-ECB(prefix || control_text || SECRET), padded.
    """
    plaintext = PREFIX + control_text + SECRET
    plaintext = pkcs7_pad(plaintext, BLOCK_SIZE)
    cipher = AES.new(GLOBAL_KEY, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

# -------------------------
# 探测：块大小 & 是否 ECB
# -------------------------
def detect_block_size():
    # 找到当输入长度增加时密文长度增长的最小步长
    initial_len = len(encryption_oracle(b""))
    i = 1
    while True:
        new_len = len(encryption_oracle(b"A" * i))
        if new_len != initial_len:
            return new_len - initial_len
        i += 1

def is_ecb():
    # 发送重复块，若密文中出现重复块则可能是 ECB
    test = b"A" * (BLOCK_SIZE * 8)
    ct = encryption_oracle(test)
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
    return len(blocks) != len(set(blocks))

# -------------------------
# 找到 prefix 的长度及对齐所需的填充
# 思路（常用技巧）：
# 发送许多相同字节（如 'A'），在某个输入长度下，密文中会出现两个连续相同的块，
# 这些连续相同块的位置能让我们推断出 prefix 的长度模 BLOCK_SIZE 的值。
# -------------------------
def find_prefix_info():
    # 我们发送不同长度的前导字节，寻找第一处在密文中出现连续重复块的位置
    # 返回 (prefix_len, padding_needed) 使得 (prefix_len + padding_needed) % BLOCK_SIZE == 0
    filler = b"A"
    # we will try increasing pad lengths
    for pad_len in range(0, BLOCK_SIZE * 2):
        probe = b"A" * pad_len + b"B" * (BLOCK_SIZE * 2)  # 两块 "B" 用来触发重复
        ct = encryption_oracle(probe)
        blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
        # search for adjacent equal blocks
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i + 1]:
                # Found repeated adjacent blocks. Now deduce prefix length:
                # The repeated pair starts at block index i.
                total_prefix_plus_pad = i * BLOCK_SIZE
                # total_prefix_plus_pad = prefix_len + pad_len
                # => prefix_len = total_prefix_plus_pad - pad_len
                prefix_len = total_prefix_plus_pad - pad_len
                prefix_len = max(0, prefix_len)
                # padding_needed is the bytes needed to align the next byte to block boundary
                padding_needed = (BLOCK_SIZE - (prefix_len % BLOCK_SIZE)) % BLOCK_SIZE
                return prefix_len, padding_needed
    raise RuntimeError("无法确定 prefix 信息（尝试多次失败）。")

# -------------------------
# 主恢复逻辑：按字节恢复 SECRET
# 考虑随机前缀，需要先 pad 使我们控制的字节从块边界开始
# -------------------------
def recover_secret(allowed_bytes=None, verbose=True):
    if allowed_bytes is None:
        # 默认把搜索字符限制在常见可打印字符，速度快且通常能恢复英文明文
        allowed_bytes = [ord(c) for c in (string.ascii_letters + string.digits + string.punctuation + " \n")]

    block_size = BLOCK_SIZE
    prefix_len, padding_needed = find_prefix_info()
    if verbose:
        print("Detected prefix_len =", prefix_len, "padding_needed =", padding_needed)

    recovered = b""
    # 计算整体密文长度（不包含我们后面加的可变pad）
    total_ct_len = len(encryption_oracle(b""))
    # 估计 secret 长度 (粗略): total_ct_len - padded(prefix_len) - padded(control_len)
    # 我们只是按位置逐字节尝试，知道何时停止（当最新字节导致匹配失败并且已到合法上限）
    # 使用 while 循环，直到我们不能再恢复更多字节
    max_secret_len = total_ct_len  # upper bound (safe)
    while True:
        i = len(recovered)
        # how many filler bytes to make the target byte be at last position of a block:
        # we want: (prefix_len + padding_needed + filler_len + (block_size-1 - (i % block_size))) % block_size == block_size-1
        # simpler: choose pad1 = padding_needed + (block_size - 1 - (i % block_size))
        pad1 = padding_needed + (block_size - 1 - (i % block_size))
        attack_input_base = b"A" * pad1

        # build dictionary of ciphertext-block -> byte for all candidate bytes
        block_index = (prefix_len + pad1) // block_size  # index of block that will contain our target
        mapping = {}
        for b in allowed_bytes:
            attempt = attack_input_base + recovered + bytes([b])
            ct = encryption_oracle(attempt)
            blocks = [ct[j:j+block_size] for j in range(0, len(ct), block_size)]
            mapping[blocks[block_index]] = bytes([b])

        # now query with attack_input_base alone and take block at block_index
        ct2 = encryption_oracle(attack_input_base)
        blocks2 = [ct2[j:j+block_size] for j in range(0, len(ct2), block_size)]
        target_block = blocks2[block_index]

        if target_block in mapping:
            recovered += mapping[target_block]
            if verbose:
                print("Recovered so far:", recovered)
            # stop condition: if we've recovered enough bytes that padding shows up and we can stop
            # crude stop: if len(recovered) > max_secret_len: break (defensive)
            if len(recovered) > max_secret_len:
                break
            continue
        else:
            # no mapping found: 可能是已经到 secret 末尾（padding）或 allowed_bytes 不够
            if verbose:
                print("No mapping for next byte — likely reached end of secret or charset incomplete.")
            break

    return recovered

# -------------------------
# 运行
# -------------------------
if __name__ == "__main__":
    bs = detect_block_size()
    print("Detected block size:", bs)
    print("Is ECB mode detected?:", is_ecb())
    secret = recover_secret(verbose=True)
    print("\nRecovered secret (bytes):")
    print(secret)
    print("\nRecovered secret (decoded if utf-8):")
    try:
        print(secret.decode())
    except:
        print("Not valid utf-8")