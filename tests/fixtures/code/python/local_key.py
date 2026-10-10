import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from vault import load_key


def local_cbc(data: bytes) -> bytes:
    key = b"0123456789abcdef"
    cipher = Cipher(algorithms.AES(key), modes.CBC(os.urandom(16)))
    return cipher.encryptor().update(data)


def local_gcm_256(data: bytes) -> bytes:
    key: bytes = b"0123456789abcdef0123456789abcdef"
    return AESGCM(key).encrypt(os.urandom(12), data, None)


def through_call(key: bytes, data: bytes) -> bytes:
    return AESGCM(key).encrypt(os.urandom(12), data, None)


def caller(data: bytes) -> bytes:
    secret = b"fedcba9876543210"
    return through_call(secret, data)


def reassigned(data: bytes) -> bytes:
    key = b"0123456789abcdef"
    key = load_key()
    return AESGCM(key).encrypt(os.urandom(12), data, None)


def extended(data: bytes) -> bytes:
    key = b"0123456789abcdef"
    key += load_key()
    return AESGCM(key).encrypt(os.urandom(12), data, None)


def generated(data: bytes) -> bytes:
    key = os.urandom(32)
    return AESGCM(key).encrypt(os.urandom(12), data, None)


def imported(data: bytes) -> bytes:
    key = load_key()
    return AESGCM(key).encrypt(os.urandom(12), data, None)


def literal_is_plaintext() -> bytes:
    key = os.urandom(16)
    payload = b"4111-1111-1111-1111"
    return AESGCM(key).encrypt(os.urandom(12), payload, None)
