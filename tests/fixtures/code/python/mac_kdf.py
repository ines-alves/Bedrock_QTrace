import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 600_000


def tag(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def tag_keyword(key: str, data: bytes) -> str:
    return hmac.new(key.encode(), data, digestmod=hashlib.sha512).hexdigest()


def tag_sha1(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha1).hexdigest()


def derive(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    return kdf.derive(password)


def derive_reordered(password: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        length=32,
        salt=os.urandom(16),
        iterations=ITERATIONS,
        algorithm=hashes.SHA1(),
    )
    return kdf.derive(password)
