import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DIGEST_NAME = "SHA256"
OTHER_NAME = "blake2b"


def new_literal() -> bytes:
    return hashlib.new("md5", b"data").digest()


def new_constant() -> bytes:
    return hashlib.new(DIGEST_NAME, b"data").digest()


def new_unresolved(name: str) -> bytes:
    return hashlib.new(name, b"data").digest()


def new_unknown_algorithm() -> bytes:
    return hashlib.new(OTHER_NAME, b"data").digest()


def new_unknown_literal() -> bytes:
    return hashlib.new("blake2b", b"data").digest()


def hmac_positional(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, "sha1").digest()


def hmac_keyword(key: bytes) -> bytes:
    return hmac.new(key, digestmod="sha256").digest()


def hmac_message_is_a_string(key: bytes) -> bytes:
    return hmac.new(key, "sha1", hashlib.sha512).digest()


def cipher_keyword_mode(key: bytes) -> object:
    return Cipher(algorithms.AES(key), mode=modes.ECB())


def cipher_keyword_both(key: bytes, iv: bytes) -> object:
    return Cipher(algorithm=algorithms.AES(key), mode=modes.CBC(iv))


def pbkdf2_positional(salt: bytes) -> object:
    return PBKDF2HMAC(hashes.SHA1(), 32, salt, 600_000)


def pbkdf2_positional_multiline(salt: bytes) -> object:
    return PBKDF2HMAC(
        hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
