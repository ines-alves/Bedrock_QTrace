from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

CURVE = ec.SECP384R1()


def p256_key():
    return ec.generate_private_key(ec.SECP256R1())


def keyword_curve():
    return ec.generate_private_key(curve=ec.SECP521R1())


def koblitz_key():
    return ec.generate_private_key(ec.SECP256K1())


def brainpool_key():
    return ec.generate_private_key(ec.BrainpoolP256R1())


def constant_curve_key():
    return ec.generate_private_key(CURVE)


def sign(private_key, payload: bytes) -> bytes:
    return private_key.sign(payload, ec.ECDSA(hashes.SHA256()))


def verify(public_key, signature: bytes, payload: bytes) -> None:
    public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
