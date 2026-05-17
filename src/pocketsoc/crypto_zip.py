from __future__ import annotations

from pathlib import Path


def encrypt_file(path: Path, password: str) -> Path:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        import os
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("cryptography package required for AES-GCM encryption") from exc

    data = path.read_bytes()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200000)
    key = kdf.derive(password.encode("utf-8"))
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, data, b"pocketsoc-bundle")
    out = path.with_suffix(path.suffix + ".enc")
    out.write_bytes(b"PSC1" + salt + nonce + ct)
    return out
