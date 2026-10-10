from cryptography.hazmat.primitives.asymmetric import dh, dsa

DH_BITS = 3072
DSA_BITS = 1024


def dh_literal():
    return dh.generate_parameters(generator=2, key_size=2048)


def dh_positional():
    return dh.generate_parameters(2, 1024)


def dh_constant():
    return dh.generate_parameters(generator=2, key_size=DH_BITS)


def dsa_keyword():
    return dsa.generate_private_key(key_size=2048)


def dsa_positional():
    return dsa.generate_private_key(1024)


def dsa_constant():
    return dsa.generate_private_key(DSA_BITS)


def dsa_parameters():
    return dsa.generate_parameters(key_size=3072)


def dsa_multiline():
    return dsa.generate_private_key(
        key_size=2048,
    )
