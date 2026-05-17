from __future__ import annotations

from pathlib import Path


def _crypto_imports():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    import os

    return AESGCM, PBKDF2HMAC, hashes, os


def encrypt_file(path: Path, password: str) -> Path:
    AESGCM, PBKDF2HMAC, hashes, os = _crypto_imports()
    data = path.read_bytes()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200000)
    key = kdf.derive(password.encode("utf-8"))
    ct = AESGCM(key).encrypt(nonce, data, b"pocketsoc-bundle")
    out = path.with_suffix(path.suffix + ".enc")
    out.write_bytes(b"PSC1" + salt + nonce + ct)
    return out


def decrypt_file(path: Path, password: str) -> Path:
    AESGCM, PBKDF2HMAC, hashes, _ = _crypto_imports()
    raw = path.read_bytes()
    if not raw.startswith(b"PSC1"):
        raise ValueError("invalid encrypted bundle format")
    salt = raw[4:20]
    nonce = raw[20:32]
    ct = raw[32:]
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200000)
    key = kdf.derive(password.encode("utf-8"))
    pt = AESGCM(key).decrypt(nonce, ct, b"pocketsoc-bundle")
    out = path.with_suffix("")
    out.write_bytes(pt)
    return out
