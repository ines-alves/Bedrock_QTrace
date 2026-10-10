from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


def mixed(data, blob):
    key = RSA.generate(2048)
    signature = pkcs1_15.new(key).sign(data)
    PKCS1_OAEP.new(key).encrypt(blob)
    return signature
