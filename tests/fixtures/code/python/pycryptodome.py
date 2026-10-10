from Crypto.Cipher import AES, ARC4, DES, DES3
from Crypto.Hash import HMAC, MD5, SHA1, SHA3_256, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import DSA, ECC
from Crypto.Random import get_random_bytes

CONST_KEY = b"fedcba9876543210"
CURVE = "p384"


def gcm_random_key(data):
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_GCM)
    return cipher.encrypt_and_digest(data)


def cbc_literal(data, iv):
    return AES.new(b"0123456789abcdef", AES.MODE_CBC, iv).encrypt(data)


def ecb_param(key, data):
    return AES.new(key, mode=AES.MODE_ECB).encrypt(data)


def eax_constant(data):
    return AES.new(CONST_KEY, AES.MODE_EAX)


def legacy(k, data):
    a = DES.new(k, DES.MODE_ECB)
    b = DES3.new(k, DES3.MODE_CBC)
    c = ARC4.new(k)
    return a, b, c


def hashes(data):
    return MD5.new(data), SHA1.new(data), SHA256.new(data), SHA3_256.new(data)


def macs(key, data):
    a = HMAC.new(key, msg=data, digestmod=SHA256)
    b = HMAC.new(key, data, SHA1)
    c = HMAC.new(key, data)
    return a, b, c


def kdfs(password, salt):
    a = PBKDF2(password, salt, 32, count=100000, hmac_hash_module=SHA256)
    b = PBKDF2(password, salt, 32, 1000, None, SHA1)
    c = PBKDF2(password, salt, 32, 1000)
    return a, b, c


def keys(name):
    a = DSA.generate(2048)
    b = ECC.generate(curve="P-256")
    c = ECC.generate(curve="ed25519")
    d = ECC.generate(curve="curve25519")
    e = ECC.generate(curve=CURVE)
    f = ECC.generate(curve=name)
    return a, b, c, d, e, f
