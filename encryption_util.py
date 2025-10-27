# -*- coding: utf-8 -*-
"""
encryption_util.py
本地保险库：AES-GCM 加密 / 解密
KDF: PBKDF2-HMAC-SHA256（默认 200_000 次）
文件格式：JSON 封装后再 Base64（bytes）保存
"""
from __future__ import annotations
import os
import json
import base64
from typing import Any, Dict

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # type: ignore
from cryptography.hazmat.primitives import hashes  # type: ignore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

VERSION = 1
PBKDF2_ITERS = 200_000
SALT_LEN = 16
NONCE_LEN = 12

def _derive_key(master_password: str, salt: bytes, iterations: int = PBKDF2_ITERS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(master_password.encode("utf-8"))

def encrypt_data(obj: Dict[str, Any], master_password: str) -> bytes:
    """
    返回可直接写入磁盘的 bytes（Base64 编码的 JSON 包）。
    """
    data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    salt = os.urandom(SALT_LEN)
    key = _derive_key(master_password, salt)
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, data, None)

    package = {
        "v": VERSION,
        "kdf": {"name": "PBKDF2-HMAC-SHA256", "iterations": PBKDF2_ITERS},
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
    }
    raw = json.dumps(package, ensure_ascii=False).encode("utf-8")
    return base64.b64encode(raw)

def decrypt_data(blob_b64: bytes, master_password: str) -> Dict[str, Any]:
    """
    读取 encrypt_data 的输出并解密还原为对象。
    """
    raw = base64.b64decode(blob_b64)
    package = json.loads(raw.decode("utf-8"))

    if int(package.get("v", 0)) != VERSION:
        raise ValueError("不支持的保险库版本。")

    salt = base64.b64decode(package["salt"])
    nonce = base64.b64decode(package["nonce"])
    ct = base64.b64decode(package["ciphertext"])
    iterations = int(package.get("kdf", {}).get("iterations", PBKDF2_ITERS))

    key = _derive_key(master_password, salt, iterations)
    aesgcm = AESGCM(key)
    data = aesgcm.decrypt(nonce, ct, None)
    return json.loads(data.decode("utf-8"))
