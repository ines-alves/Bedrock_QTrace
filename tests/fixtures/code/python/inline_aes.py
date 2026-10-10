import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from vault import IMPORTED_KEY


def cbc_128(data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(b"0123456789abcdef"), modes.CBC(os.urandom(16)))
    return cipher.encryptor().update(data)


def gcm_256(data: bytes) -> bytes:
    return AESGCM(b"0123456789abcdef0123456789abcdef").encrypt(os.urandom(12), data, None)


def ecb_keyword(data: bytes) -> bytes:
    return Cipher(algorithms.AES(key=b"0123456789abcdef"), modes.ECB()).encryptor().update(data)


def gcm_192(data: bytes) -> bytes:
    return AESGCM(b"0123456789abcdef01234567").encrypt(os.urandom(12), data, None)


def imported(data: bytes) -> bytes:
    return AESGCM(IMPORTED_KEY).encrypt(os.urandom(12), data, None)


def generated(data: bytes) -> bytes:
    return AESGCM(os.urandom(32)).encrypt(os.urandom(12), data, None)
