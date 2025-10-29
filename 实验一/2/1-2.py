import string
from itertools import product
ciphertext = '486f7720646f6573206120626173746172642c206f727068616e2c20736f6e206f6620612077686f726520416e6420612053636f74736d616e2c2064726f7070656420696e20746865206d6964646c65206f66206120666f72676f7474656e2073706f7420496e207468652043617269626265616e2062792070726f766964656e636520696d706f766572697368656420496e20737175616c6f722c2067726f7720757020746f2062652061206865726f20616e642061207363686f6c61723f205468652074656e2d646f6c6c617220666f756e64696e672066617468657220776974686f757420612066617468657220476f742061206c6f74206661727468657220627920776f726b696e672061206c6f7420686172646572204279206265696e672061206c6f7420736d6172746572204279206265696e6720612073656c662d7374617274657220427920666f75727465656e2c207468657920706c616365642068696d20696e20636861726765206f6620612074726164696e67206368617274652e20416e6420657665727920646179207768696c6520736c617665732077657265206265696e6720736c61756768746572656420616e64206361727465642061776179204163726f7373207468652077617665732c206865207374727567676c656420616e64206b6570742068697320677561726420757020496e736964652c20686520776173206c6f6e67696e6720666f7220736f6d657468696e6720746f20626520612070617274206f66205468652062726f746865722077617320726561647920746f206265672c20737465616c2c20626f72726f772c206f72206261727465722e205468656e206120687572726963616e652063616d652c20616e64206465766573746174696f6e20726569676e6564204f7572206d616e20736177206869732066757475726520647269702c206472697070696e6720646f776e2074686520647261696e202e2e2e'

def hex_to_bytes(hex_text):
    return bytes.fromhex(hex_text)

def transpose_columns(ct_bytes, key_len):
    return [ct_bytes[i::key_len] for i in range(key_len)]

ct = hex_to_bytes(ciphertext)
cols = transpose_columns(ct, 7)

for i, c in enumerate(cols):
    print(f'列 {i}（长度 {len(c)}）: {c.hex()}')

# 将十六进制字符串转换为整数列表（每个元素 0..255）
def hex_to_bytes_list(h):
    return [int(h[i:i+2], 16) for i in range(0, len(h), 2)]

# 给定一组字节（来自同一个密钥位置的周期性划分），返回可能的 key 值集合
def candidate_keys_for_column(byte_group, allowed_chars):
    candidates = set()
    for k in range(256):
        ok = True
        for b in byte_group:
            if (b ^ k) not in allowed_chars:
                ok = False
                break
        if ok:
            candidates.add(k)
    return candidates

# 评分/打印辅助：把 key 列表转换为可读明文（尽量只做演示）
def decrypt_with_key_sequence(ct_bytes, key_sequence):
    out_chars = []
    L = len(key_sequence)
    for i, b in enumerate(ct_bytes):
        k = key_sequence[i % L]
        out_chars.append(chr(b ^ k))
    return ''.join(out_chars)

# 允许的明文字节集合（可根据需要放宽）
allowed = set(ord(c) for c in (string.ascii_letters + string.digits + ' .,!?;:\'\"()-'))

ct_bytes = hex_to_bytes_list(ciphertext)

# 试探 key 长度（1..13）
found_length = None
candidates_by_pos = None
for guess_len in range(1, 14):
    all_ok = True
    pos_candidates = []
    for pos in range(guess_len):
        column = ct_bytes[pos::guess_len]
        keys = candidate_keys_for_column(column, allowed)
        if not keys:
            all_ok = False
            break
        pos_candidates.append(sorted(keys))
    if all_ok:
        found_length = guess_len
        candidates_by_pos = pos_candidates
        print(f"可能的密钥长度: {guess_len}")
        # 打印每个位置的候选 key（限数量）
        for idx, cand in enumerate(pos_candidates):
            print(f"  位置 {idx}: {len(cand)} 个候选，示例: {cand[:8]}")
        # break

if not candidates_by_pos:
    print("未能找到满足约束的密钥长度（请放宽 allowed 字符集）")
else:
    chosen_key = [candidates_by_pos[i][0] for i in range(found_length)]
    plaintext_guess = decrypt_with_key_sequence(ct_bytes, chosen_key)
    print("\n使用每列第一个候选 key 解密的初步结果：")
    print(plaintext_guess)

    #eg
    limited_candidates = [cand[:3] for cand in candidates_by_pos]  # 每列只取最多 3 个
    print("\n尝试受限的候选组合（每列最多 3 个候选）……")
    best = None
    for combo in product(*limited_candidates):
        text = decrypt_with_key_sequence(ct_bytes, combo)
        # 简单评分：计算常见英文单词出现次数
        score = sum(text.count(w) for w in (" the ", " and ", " of ", " to ", " is "))
        if best is None or score > best[0]:
            best = (score, combo, text)
    if best:
        print(f"\n最佳组合评分 {best[0]}，使用的 key: {best[1]}")
        print(best[2])