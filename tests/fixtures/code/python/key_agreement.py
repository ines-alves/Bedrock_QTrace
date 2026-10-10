from cryptography.hazmat.primitives.asymmetric import ec, x448, x25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def x25519_pair():
    return x25519.X25519PrivateKey.generate()


def x25519_imported_name():
    return X25519PrivateKey.generate()


def x25519_peer(raw: bytes):
    return x25519.X25519PublicKey.from_public_bytes(raw)


def x448_pair():
    return x448.X448PrivateKey.generate()


def ecdh_shared(private_key, peer_public_key) -> bytes:
    return private_key.exchange(ec.ECDH(), peer_public_key)
