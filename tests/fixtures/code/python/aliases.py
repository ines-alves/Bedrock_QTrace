import hashlib as h
import random as rnd
from hashlib import md5
from hashlib import sha1 as s1

from cryptography.hazmat.primitives import hashes as H
from cryptography.hazmat.primitives.asymmetric import padding as P
from cryptography.hazmat.primitives.asymmetric import rsa as R
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as EdKey
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms as A
from cryptography.hazmat.primitives.ciphers import modes as M
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as GCM

BITS = 1024
KEY = b"0123456789ABCDEF"


def digest_module_alias(data):
    return h.md5(data)


def digest_from_import(data):
    return md5(data)


def digest_from_import_alias(data):
    return s1(data)


def digest_class_alias():
    return H.SHA256()


def token():
    return rnd.getrandbits(32)


def new_signing_key():
    return EdKey.generate()


def sign(message):
    key = R.generate_private_key(public_exponent=65537, key_size=BITS)
    return key.sign(message, P.PKCS1v15(), H.SHA256())


def encrypt_ecb(data):
    cipher = Cipher(A.AES(KEY), M.ECB())
    return cipher.encryptor().update(data)


def encrypt_gcm(nonce, data):
    return GCM(KEY).encrypt(nonce, data, None)
