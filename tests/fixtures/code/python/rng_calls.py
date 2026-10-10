import os
import random
import secrets


def weak_token() -> bytes:
    return bytes(random.getrandbits(8) for _ in range(16))


def weak_bytes() -> bytes:
    return random.randbytes(16)


def strong_token() -> bytes:
    return os.urandom(16)


def strong_hex() -> str:
    return secrets.token_hex(16)
