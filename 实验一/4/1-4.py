import hashlib
import itertools
import time

# === 配置部分 ===
TARGET_SHA1 = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"
CHAR_OPTIONS = [
    ['Q', 'q'],
    ['W', 'w'],
    ['5', '%'],
    ['8', '('],
    ['=', '0'],
    ['I', 'i'],
    ['*', '+'],
    ['n', 'N']
]

# === 工具函数 ===
def sha1_hash(text: str) -> str:
    """返回字符串的 SHA1 哈希值"""
    return hashlib.sha1(text.encode()).hexdigest()

# === 暴力破解核心逻辑 ===
start_time = time.time()
base_password = list("0" * 8)  # 初始化占位

for i in range(2):
    base_password[0] = CHAR_OPTIONS[0][i]
    for j in range(2):
        base_password[1] = CHAR_OPTIONS[1][j]
        for k in range(2):
            base_password[2] = CHAR_OPTIONS[2][k]
            for l in range(2):
                base_password[3] = CHAR_OPTIONS[3][l]
                for m in range(2):
                    base_password[4] = CHAR_OPTIONS[4][m]
                    for n in range(2):
                        base_password[5] = CHAR_OPTIONS[5][n]
                        for o in range(2):
                            base_password[6] = CHAR_OPTIONS[6][o]
                            for p in range(2):
                                base_password[7] = CHAR_OPTIONS[7][p]

                                # 构造当前组合的所有排列
                                candidate_chars = "".join(base_password)
                                for perm in itertools.permutations(candidate_chars, 8):
                                    candidate_pwd = "".join(perm)
                                    hashed = sha1_hash(candidate_pwd)

                                    if hashed == TARGET_SHA1:
                                        print("✅ Password found:", candidate_pwd)
                                        end_time = time.time()
                                        print(f"⏱ Time used: {end_time - start_time:.2f}s")
                                        exit(0)