from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


def sign(data):
    key = RSA.generate(2048)
    return pkcs1_15.new(key).sign(SHA256.new(data))


def encrypt(data):
    other = RSA.generate(3072)
    return PKCS1_OAEP.new(other.publickey()).encrypt(data)
