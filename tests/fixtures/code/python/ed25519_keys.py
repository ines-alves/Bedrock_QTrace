from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def qualified():
    return ed25519.Ed25519PrivateKey.generate()


def imported_name():
    return Ed25519PrivateKey.generate()


def sign_only(private_key, payload: bytes) -> bytes:
    return private_key.sign(payload)
