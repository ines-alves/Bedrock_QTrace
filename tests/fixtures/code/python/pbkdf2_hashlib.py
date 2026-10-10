import hashlib
import hashlib as hl
from hashlib import pbkdf2_hmac as stretch

KDF_HASH = "sha512"
OTHER_HASH = "blake2b"


def literal(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, 600_000)


def weak_sha1(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", password, salt, 1000, dklen=32)


def keyword_name(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(hash_name="sha384", password=password, salt=salt, iterations=600_000)


def constant_name(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(KDF_HASH, password, salt, 600_000)


def aliased_module(password: bytes, salt: bytes) -> bytes:
    return hl.pbkdf2_hmac("sha256", password, salt, 600_000)


def aliased_function(password: bytes, salt: bytes) -> bytes:
    return stretch("sha256", password, salt, 600_000)


def unresolved_name(name: str, password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(name, password, salt, 600_000)


def unknown_constant(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(OTHER_HASH, password, salt, 600_000)


def unknown_literal(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("blake2b", password, salt, 600_000)


def literal_password(salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", b"correct horse battery", salt, 600_000)


def other_module(legacy, password: bytes, salt: bytes) -> bytes:
    return legacy.pbkdf2_hmac("sha1", password, salt, 10)
