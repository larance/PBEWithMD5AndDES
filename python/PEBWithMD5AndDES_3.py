import base64
import hashlib
import os
from Crypto.Cipher import DES


def get_derived_key(password: bytes, salt: bytes, count: int = 1000):
    """改进的密钥派生函数"""
    key = password + salt
    for _ in range(count):
        key = hashlib.md5(key).digest()
    return key[:8], key[8:]


def add_pkcs5_padding(data: bytes) -> bytes:
    """添加 PKCS#5/PKCS#7 填充"""
    pad_len = 8 - (len(data) % 8)
    padding = bytes([pad_len] * pad_len)
    return data + padding


def remove_pkcs5_padding(data: bytes) -> bytes:
    """移除 PKCS#5/PKCS#7 填充"""
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding")
    # 验证所有填充字节是否正确
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding")
    return data[:-pad_len]


def encrypt_improved(plaintext: str, password: str) -> str:
    """改进的加密函数"""
    # 转换为字节
    plaintext_bytes = plaintext.encode('utf-8')
    password_bytes = password.encode('utf-8')

    # 生成随机盐
    salt = os.urandom(8)

    # 添加填充
    padded_data = add_pkcs5_padding(plaintext_bytes)

    # 派生密钥和 IV
    key, iv = get_derived_key(password_bytes, salt)

    # 创建 DES-CBC 加密器
    cipher = DES.new(key, DES.MODE_CBC, iv)

    # 加密
    ciphertext = cipher.encrypt(padded_data)

    # 返回 Base64 编码的（盐 + 密文）
    return base64.b64encode(salt + ciphertext).decode('utf-8')


def decrypt_improved(encrypted: str, password: str) -> str:
    """改进的解密函数"""
    # 转换为字节
    password_bytes = password.encode('utf-8')

    # Base64 解码
    data = base64.b64decode(encrypted)

    # 提取盐和密文
    salt = data[:8]
    ciphertext = data[8:]

    # 派生密钥和 IV
    key, iv = get_derived_key(password_bytes, salt)

    # 创建 DES-CBC 解密器
    cipher = DES.new(key, DES.MODE_CBC, iv)

    # 解密
    padded_plaintext = cipher.decrypt(ciphertext)

    # 移除填充
    plaintext_bytes = remove_pkcs5_padding(padded_plaintext)

    return plaintext_bytes.decode('utf-8')


def test_improved():
    """测试改进版本"""
    msg = "Hello, World!"
    password = "mysecretpassword"

    print("原始消息:", msg)

    # 加密
    encrypted = encrypt_improved(msg, password)
    print("加密后:", encrypted)

    # 解密
    decrypted = decrypt_improved(encrypted, password)
    print("解密后:", decrypted)

    # 验证
    assert msg == decrypted, "解密结果与原始消息不匹配"
    print("✓ 测试通过")


if __name__ == "__main__":
    test_improved()
