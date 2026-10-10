import hashlib
import hmac

from cryptography.hazmat.primitives import hashes


def md5_digest(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def sha1_digest(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def sha384_digest(data: bytes) -> str:
    return hashlib.sha384(data).hexdigest()


def sha256_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def cryptography_md5(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.MD5())
    digest.update(data)
    return digest.finalize()


def same_digest(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


# hashlib.md5(b"mentioned in a comment only")
