import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

EXPORT_KEY = b"0123456789ABCDEF"
KEY_LEN = 32


def ecb_with_default(plaintext: bytes, key: bytes = EXPORT_KEY) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    return cipher.encryptor().update(plaintext)


def cbc_unknown_key(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    return cipher.encryptor().update(plaintext)


def generate_key() -> bytes:
    return os.urandom(KEY_LEN)


def gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, None)


def run() -> bytes:
    key = generate_key()
    return gcm_encrypt(key, os.urandom(12), b"data")
