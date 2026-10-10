from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2


def hmac_default(key, data):
    return HMAC.new(key, data)


def hmac_default_keywords(key, data):
    return HMAC.new(key=key, msg=data)


def hmac_key_only(key):
    return HMAC.new(key)


def hmac_keyword_digest(key, data):
    return HMAC.new(key, data, digestmod=SHA256)


def hmac_positional_digest(key, data):
    return HMAC.new(key, data, SHA256)


def hmac_star(args):
    return HMAC.new(*args)


def pbkdf2_all_defaults(password, salt):
    return PBKDF2(password, salt)


def pbkdf2_default_hash_explicit_count(password, salt):
    return PBKDF2(password, salt, 32, 600000)


def pbkdf2_count_keyword(password, salt):
    return PBKDF2(password, salt, count=2000)


def pbkdf2_hash_explicit_default_count(password, salt):
    return PBKDF2(password, salt, 32, hmac_hash_module=SHA256)


def pbkdf2_explicit_all(password, salt):
    return PBKDF2(password, salt, 32, 8000, None, SHA256)


def pbkdf2_prf(password, salt, prf):
    return PBKDF2(password, salt, 32, 1000, prf=prf)


def pbkdf2_star(password, rest):
    return PBKDF2(password, *rest)


def pbkdf2_unresolved_count(password, salt, rounds):
    return PBKDF2(password, salt, 32, rounds)
