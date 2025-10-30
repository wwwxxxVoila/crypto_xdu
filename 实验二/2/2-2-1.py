# PKCS#7 填充与去填充实现
# 实现目标：让消息长度是 block_size 的整数倍

def pad(message: bytes, block_size: int) -> bytes:
    """
    给消息添加 PKCS#7 填充
    """
    # 计算需要补多少个字节
    padding_len = block_size - (len(message) % block_size)
    
    # 如果刚好是整块，也要补一个整块（PKCS#7要求）
    if padding_len == 0:
        padding_len = block_size
    
    # 构造填充字节（例如要补4个字节 -> b'\x04\x04\x04\x04'）
    padding_bytes = bytes([padding_len] * padding_len)
    
    # 打印调试信息（学习时方便看）
    print(f"[DEBUG] Padding length: {padding_len}")
    print(f"[DEBUG] Padding bytes: {padding_bytes}")
    
    return message + padding_bytes


def unpad(message: bytes) -> bytes:
    """
    去除 PKCS#7 填充
    """
    if len(message) == 0:
        raise ValueError("输入消息为空，无法去除填充！")
    
    # 取出最后一个字节，它的值表示填充长度
    padding_len = message[-1]
    
    # 做一些合法性检查
    if padding_len == 0 or padding_len > len(message):
        raise ValueError("填充长度不合法！")
    
    # 检查末尾是否真的都是一样的填充值
    if message[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("填充格式错误，可能数据被破坏。")
    
    return message[:-padding_len]


#测试喵pytho
plain = b"YELLOW SUBMARINE"
print("原始消息：", plain)

padded = pad(plain, 16)
print("填充后的结果：", padded)

unpadded = unpad(padded)
print("去填充后的结果：", unpadded)
