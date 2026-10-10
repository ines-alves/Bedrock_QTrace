import hashlib
import os

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROUNDS = 210_000
ENV_ROUNDS = int(os.environ.get("ROUNDS", "1"))


def literal(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, 1000)


def keyword(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations=600_000, dklen=32)


def constant(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, ROUNDS)


def computed(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, ROUNDS * 2)


def from_environment(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, ENV_ROUNDS)


def param_default(password: bytes, salt: bytes, rounds: int = 300_000) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, rounds)


def one_hop(password: bytes, salt: bytes, rounds: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, rounds)


def sites_agree(password: bytes, salt: bytes, rounds: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, rounds)


def sites_disagree(password: bytes, salt: bytes, rounds: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, rounds)


def two_hops(password: bytes, salt: bytes, rounds: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, rounds)


def middle(password: bytes, salt: bytes, rounds: int) -> bytes:
    return two_hops(password, salt, rounds)


def cryptography_keyword(salt: bytes) -> PBKDF2HMAC:
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=2000)


def cryptography_positional(salt: bytes) -> PBKDF2HMAC:
    return PBKDF2HMAC(hashes.SHA1(), 32, salt, 5000)


def pycryptodome_keyword(password: bytes, salt: bytes) -> bytes:
    return PBKDF2(password, salt, 32, count=4000, hmac_hash_module=SHA256)


def pycryptodome_positional(password: bytes, salt: bytes) -> bytes:
    return PBKDF2(password, salt, 32, 8000, None, SHA256)


def pycryptodome_default_count(password: bytes, salt: bytes) -> bytes:
    return PBKDF2(password, salt, 32, hmac_hash_module=SHA256)


one_hop(b"p", b"s", 50_000)
sites_agree(b"p", b"s", 7000)
sites_agree(b"q", b"s", 7000)
sites_disagree(b"p", b"s", 1000)
sites_disagree(b"p", b"s", 600_000)
middle(b"p", b"s", 9000)
