import base64
import hashlib
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_MAGIC = b"SSENC1"
_NONCE_LEN = 12


def _to_bytes(data) -> bytes:
    if data is None:
        raise ValueError("Data cannot be None")
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, memoryview):
        return data.tobytes()
    raise TypeError(f"Unsupported data type for encryption: {type(data).__name__}")


def _normalize_key(raw_key: str) -> bytes:
    raw_key = (raw_key or "").strip()
    if not raw_key:
        raise ValueError("Missing encryption key")

    try:
        decoded = base64.urlsafe_b64decode(raw_key + "=" * (-len(raw_key) % 4))
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass

    if len(raw_key.encode("utf-8")) == 32:
        return raw_key.encode("utf-8")

    return hashlib.sha256(raw_key.encode("utf-8")).digest()


def get_app_encryption_key() -> bytes:
    env_key = os.getenv("FILE_ENCRYPTION_KEY")
    if env_key:
        return _normalize_key(env_key)

    fallback = os.getenv("SECRET_KEY", "dev-insecure-file-key")
    return hashlib.sha256(fallback.encode("utf-8")).digest()


def is_encrypted_blob(data: Optional[bytes]) -> bool:
    if not data:
        return False
    return _to_bytes(data).startswith(_MAGIC)


def encrypt_bytes(plain_data: bytes, key: Optional[bytes] = None) -> bytes:
    plain_data = _to_bytes(plain_data)

    key = key or get_app_encryption_key()

    if is_encrypted_blob(plain_data):
        return plain_data

    nonce = os.urandom(_NONCE_LEN)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, plain_data, None)
    return _MAGIC + nonce + ciphertext


def decrypt_bytes(blob_data: bytes, key: Optional[bytes] = None) -> bytes:
    blob_data = _to_bytes(blob_data)

    key = key or get_app_encryption_key()

    if not is_encrypted_blob(blob_data):
        return blob_data

    nonce_start = len(_MAGIC)
    nonce_end = nonce_start + _NONCE_LEN
    nonce = blob_data[nonce_start:nonce_end]
    ciphertext = blob_data[nonce_end:]

    if len(nonce) != _NONCE_LEN or not ciphertext:
        raise ValueError("Invalid encrypted blob format")

    cipher = AESGCM(key)
    return cipher.decrypt(nonce, ciphertext, None)
