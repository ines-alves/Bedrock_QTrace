import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from vault import IMPORTED_KEY

CONST_KEY = b"0123456789ABCDEF"
DEFAULT_KEY = b"fedcba9876543210"
HOP_KEY = b"hop-key-0123456789"
MAC_KEY = b"shared-signing-key-32-bytes-long"
SALT = b"fixed-salt-value"
OVERWRITTEN_KEY = b"overwritten-key-01"


def from_constant(data: bytes) -> bytes:
    return AESGCM(CONST_KEY).encrypt(os.urandom(12), data, None)


def from_default(data: bytes, key: bytes = DEFAULT_KEY) -> bytes:
    return Cipher(algorithms.AES(key), modes.CBC(os.urandom(16))).encryptor().update(data)


def inline(data: bytes) -> bytes:
    return AESGCM(b"inline-key-012345").encrypt(os.urandom(12), data, None)


def with_key(key: bytes, data: bytes) -> bytes:
    return AESGCM(key).encrypt(os.urandom(12), data, None)


def through_call_site(data: bytes) -> bytes:
    return with_key(HOP_KEY, data)


def mac_tag(data: bytes) -> bytes:
    return hmac.new(MAC_KEY, data, hashlib.sha256).digest()


def salted_digest(data: bytes) -> str:
    return hashlib.sha256(SALT + data).hexdigest()


def random_key(data: bytes) -> bytes:
    key = os.urandom(32)
    return AESGCM(key).encrypt(os.urandom(12), data, None)


def imported_key(data: bytes) -> bytes:
    return AESGCM(IMPORTED_KEY).encrypt(os.urandom(12), data, None)


def default_overwritten(data: bytes, key: bytes = OVERWRITTEN_KEY) -> bytes:
    key = os.urandom(32)
    return AESGCM(key).encrypt(os.urandom(12), data, None)
