import hashlib
import hashlib as hl
from hashlib import scrypt as stretch


def direct(password: bytes, salt: bytes) -> bytes:
    return hashlib.scrypt(password, salt=salt, n=2**14, r=8, p=1)


def aliased_module(password: bytes, salt: bytes) -> bytes:
    return hl.scrypt(password, salt=salt, n=2**15, r=8, p=1, dklen=32)


def aliased_function(password: bytes, salt: bytes) -> bytes:
    return stretch(password, salt=salt, n=2**14, r=8, p=1)


def literal_password(salt: bytes) -> bytes:
    return hashlib.scrypt(b"correct horse battery", salt=salt, n=2**14, r=8, p=1)


def other_module(legacy, password: bytes, salt: bytes) -> bytes:
    return legacy.scrypt(password, salt=salt, n=16384, r=8, p=1)
