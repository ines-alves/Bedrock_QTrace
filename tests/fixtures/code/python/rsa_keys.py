from cryptography.hazmat.primitives.asymmetric import rsa

BITS = 3072


def make_literal():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def make_constant():
    return rsa.generate_private_key(public_exponent=65537, key_size=BITS)


def make_positional():
    return rsa.generate_private_key(65537, 2048)


def make_multiline():
    return rsa.generate_private_key(
        key_size=4096,
        public_exponent=65537,
    )
