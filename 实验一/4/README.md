4.	MTC3 Cracking SHA1-Hashed Passwords
https://www.mysterytwisterc3.org/en/challenges/level-2/cracking-sha1-hashed-passwords

是用 暴力破解 SHA1 哈希，通过枚举 8 个字符（每个字符两种可能）以及它们的全排列，找到与目标哈希匹配的明文密码。

实验原理

1. SHA1 简介

SHA1（Secure Hash Algorithm 1）是一种常见的 单向散列函数，可以将任意长度的输入数据映射为 40 位十六进制字符串（160 bit）。
其特征是：
	•	不可逆：无法直接从哈希值反推原始明文；
	•	固定长度输出：输入多长都输出 160 位；
	•	抗碰撞性：理论上不同输入对应不同输出；
	•	敏感性高：输入微小变化会导致输出完全不同。

2. 暴力破解（Brute Force）

暴力破解是一种通过穷举所有可能密码组合来找到与目标哈希值相匹配的明文的方法。
其核心思想是：

“既然哈希不可逆，那我就把所有可能的明文都哈希一遍，看哪个结果一样。”

这种方法虽然通用，但计算复杂度极高，密码长度每增加 1 位，搜索空间就会指数增长。


实验代码结构分析

```
import hashlib
import itertools
import time
```

目标哈希值（我们要反推出原始密码）
SHA1_HASH_TARGET = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"

每一位密码可能的取值集合（8 位密码，每位有 2 种可能）
CHAR_SETS = [
    ['Q', 'q'],
    ['W', 'w'],
    ['5', '%'],
    ['8', '('],
    ['=', '0'],
    ['I', 'i'],
    ['*', '+'],
    ['n', 'N']
]

这部分定义了：
	•	要破解的哈希目标；
	•	每一位密码的取值范围。
例如：第一位只能是 'Q' 或 'q'，第二位是 'W' 或 'w'，以此类推。


3. SHA1 加密函数

```
def sha1_encrypt(input_string):
    sha = hashlib.sha1(input_string.encode())
    return sha.hexdigest()
```

这个函数用 hashlib 库计算字符串的 SHA1 值，并返回十六进制表示。


4. 暴力穷举部分

核心循环如下：

```
for i in range(2):
    for j in range(2):
        ...
            for p in range(2):
                candidate = [CHAR_SETS[0][i], ..., CHAR_SETS[7][p]]
                permutation = "".join(candidate)
                for perm in itertools.permutations(permutation, 8):
                    candidate_password = "".join(perm)
                    hashed_candidate = sha1_encrypt(candidate_password)
                    if hashed_candidate == SHA1_HASH_TARGET:
                        print("password:", candidate_password)
                        ...
                        exit(0)
```

解释如下：
	1.	外层 8 重循环
遍历每一位密码的两种可能，共 2^8 = 256 种字符组合。
	2.	itertools.permutations(permutation, 8)
对当前 8 个字符进行全排列，生成 8! = 40320 种排列。
因此理论总搜索空间是：
256 \times 8! = 256 \times 40320 = 10,321,920
大约一千万次哈希计算。
	3.	哈希比对
每生成一个候选密码 candidate_password，就计算其 SHA1 值；
若与目标哈希匹配，输出密码并终止程序。
	4.	时间统计
用 time.time() 记录程序运行时长，衡量破解效率。
