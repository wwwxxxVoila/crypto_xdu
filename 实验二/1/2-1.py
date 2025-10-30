from hashlib import sha1
from base64 import b64decode
from Crypto.Cipher import AES

cipher_text_b64 = '9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI'
mrz_raw = '12345678<8<<<1110182<111116?<<<<<<<<<<<<<<<4'


def fill_check_digit(mrz_str: str) -> str:
    """
    根据 MRZ 校验算法计算并填充校验位（文献[2]公式）。
    """
    mrz = list(mrz_str)
    weights = [7, 3, 1, 7, 3, 1]
    total = 0
    for i in range(21, 27):
        total = (total + int(mrz[i]) * weights[i - 21]) % 10
    mrz[27] = str(total)
    return ''.join(mrz)


def derive_kseed(mrz_str: str) -> str:
    """
    根据 MRZ 信息生成 K_seed。
    """
    mrz_concat = mrz_str[:10] + mrz_str[13:20] + mrz_str[21:28]
    sha1_hash = sha1(mrz_concat.encode()).hexdigest()
    return sha1_hash[:32]


def add_parity_bits(hex_str: str) -> str:
    """
    对每个字节添加偶校验位（DES 密钥格式要求）。
    """
    bits = bin(int(hex_str, 16))[2:]
    parity_bits = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i + 7]
        parity_bit = '1' if byte.count('1') % 2 == 0 else '0'
        parity_bits.append(byte + parity_bit)
    return hex(int(''.join(parity_bits), 2))[2:]


def derive_session_key(kseed_hex: str) -> str:
    """
    通过 K_seed 生成完整 AES Key。
    """
    kseed_with_const = kseed_hex + '00000001'
    sha1_digest = sha1(bytes.fromhex(kseed_with_const)).hexdigest()
    return add_parity_bits(sha1_digest[:16]) + add_parity_bits(sha1_digest[16:32])


def decrypt_passport_data(cipher_b64: str, key_hex: str) -> str:
    """
    使用派生出的 AES Key 对电子护照数据进行解密。
    """
    ciphertext = b64decode(cipher_b64)
    iv = bytes.fromhex('0' * 32)
    aes = AES.new(bytes.fromhex(key_hex), AES.MODE_CBC, iv)
    plaintext = aes.decrypt(ciphertext)
    return plaintext.decode(errors='ignore')


if __name__ == '__main__':
    mrz_filled = fill_check_digit(mrz_raw)
    kseed = derive_kseed(mrz_filled)
    aes_key = derive_session_key(kseed)
    plaintext = decrypt_passport_data(cipher_text_b64, aes_key)

    print("Filled MRZ:", mrz_filled)
    print("K_seed:", kseed)
    print("AES Key:", aes_key)
    print("Decrypted Plaintext:", plaintext)