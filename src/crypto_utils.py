import os
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_keys():
    """生成 RSA 密钥对"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """将公钥序列化为 PEM 格式的 bytes"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_public_key(pem_data):
    """从 PEM 格式加载公钥"""
    return serialization.load_pem_public_key(pem_data)

def encrypt_message(message: str, recipient_public_key) -> str:
    """
    使用混合加密方案加密消息:
    1. 生成随机 AES 密钥
    2. 使用 AES-GCM 加密消息
    3. 使用接收者的 RSA 公钥加密 AES 密钥
    4. 返回打包后的数据 (Base64 编码的 JSON)
    """
    # 1. 生成 AES 密钥 (32 bytes for AES-256) 和 Nonce (12 bytes for GCM)
    aes_key = os.urandom(32)
    nonce = os.urandom(12)

    # 2. AES-GCM 加密
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    tag = encryptor.tag

    # 3. RSA 加密 AES 密钥
    encrypted_aes_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 4. 打包
    package = {
        'enc_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }
    return json.dumps(package)

def decrypt_message(package_json: str, private_key) -> str:
    """
    解密消息:
    1. 解析 JSON
    2. 使用 RSA 私钥解密 AES 密钥
    3. 使用 AES-GCM 解密消息
    """
    try:
        package = json.loads(package_json)
        
        encrypted_aes_key = base64.b64decode(package['enc_key'])
        nonce = base64.b64decode(package['nonce'])
        tag = base64.b64decode(package['tag'])
        ciphertext = base64.b64decode(package['ciphertext'])

        # 1. 解密 AES 密钥
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 2. 解密消息
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"[Decryption Failed: {str(e)}]"
