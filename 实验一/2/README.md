2.	PA1 option 
Write a program that allows you to "crack" ciphertexts generated using a Vigenere-like cipher, where byte-wise XOR is used instead of addition modulo 26. 

其实刚开始我是不太会写的 因为题目要求是自己写一个 然后我搜索了b站一些视频啥的。在代码里ciphertext我出于私心选了一段歌词hhh:How does a bastard, orphan, son of a whore And a Scotsman, dropped in the middle of a forgotten spot In the Caribbean by providence impoverished In squalor, grow up to be a hero and a scholar? The ten-dollar founding father without a father Got a lot farther by working a lot harder By being a lot smarter By being a self-starter By fourteen, they placed him in charge of a trading charte. And every day while slaves were being slaughtered and carted away Across the waves, he struggled and kept his guard up Inside, he was longing for something to be a part of The brother was ready to beg, steal, borrow, or barter. Then a hurricane came, and devastation reigned Our man saw his future drip, dripping down the drain ...然后让ai先帮我转了编码

然后我不太会所以问了同学 顺便放一个用她代码跑出来的结果 经过同学讲解我醍醐灌顶

解释

这是一种维吉尼亚加密的变体：
	•	普通维吉尼亚加密：C = (P + K) mod 26
  
	•	本题变体加密：C = P XOR K（XOR是异或运算，逐字节进行）

所以破解目标就是：已知密文 ciphertext，找出可能的 key（或 key 长度），再还原明文。

整个程序分为三步：

	1.	把十六进制密文转成数字列表（字节）
  
	2.	尝试不同的 key 长度，枚举出每个位置可能的 key 值
  
	3.	用猜到的 key 还原明文


函数

1️⃣ hex_to_ascii(hex_text)

def hex_to_ascii(hex_text):
    ascii_list = []
    for i in range(0, len(hex_text), 2):
        ascii_list.append(int(hex_text[i:i + 2], 16))
    return ascii_list

功能：把密文从字符串 'F9 6D E8 C2 ...' 变成字节数组 [249, 109, 232, 194, ...]。

原理：每两个字符是一组16进制（例如 "F9" = 0xF9 = 249），便于之后 XOR 运算。


2️⃣ find_possible_keys(byte_group)

def find_possible_keys(byte_group):
    valid_chars = string.ascii_letters + ',' + '.' + ' '
    potential_keys = []
    confirmed_keys = []
    for i in range(0x00, 0xFF):
        potential_keys.append(i)
        confirmed_keys.append(i)
    for key in potential_keys:
        for byte in byte_group:
            if chr(key ^ byte) not in valid_chars:
                confirmed_keys.remove(key)
                break
    return confirmed_keys

功能：对于密文字节分组（同一key位置的字节们），枚举所有可能的 key 值，看哪些能解出正常英文字符。

过程：valid_chars 定义了“合法明文字”：字母、空格、逗号、句号。遍历 key = 0x00 ~ 0xFE；对于每个 key，把 byte XOR key 得到明文字节；如果结果不是合法字符，就排除这个 key；返回剩下的 key 候选集。


3️⃣ 主程序：猜 key 长度、构建 key

cipher_bytes = hex_to_ascii(ciphertext)
actual_key_length = 0
vigenere_like_keys = []
for length in range(1, 14):
    temp_keys = []
    for index in range(0, length):
        byte_group = cipher_bytes[index::length]
        keys = find_possible_keys(byte_group)
        if not keys:
            break
        else:
            temp_keys.insert(index, keys)
    if temp_keys:
        actual_key_length = length
        vigenere_like_keys = temp_keys
        print(length)
        print(f"key:{temp_keys}")

逻辑：尝试 key 长度从 1 到 13。把密文分成 length 组（每组代表相同位置的key加密的字节）。调用 find_possible_keys() 统计每个位置的可能 key。如果全部位置都找到合法 key，则可能是正确长度。记录下来。


4️⃣ 解密还原明文

decrypted_text = ''
for i in range(0, len(cipher_bytes)):
    decrypted_text = decrypted_text + chr(cipher_bytes[i] ^ vigenere_like_keys[i % actual_key_length][0])
print(decrypted_text)

逻辑：用猜出的 key（取每个位置候选 key 的第一个）解密；输出得到的明文字符串。


