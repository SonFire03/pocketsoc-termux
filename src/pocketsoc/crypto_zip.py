from __future__ import annotations

import hashlib
from pathlib import Path


def _keystream(password: str, n: int) -> bytes:
    seed = hashlib.sha256(password.encode("utf-8")).digest()
    out = bytearray()
    ctr = 0
    while len(out) < n:
        blk = hashlib.sha256(seed + ctr.to_bytes(8, "big")).digest()
        out.extend(blk)
        ctr += 1
    return bytes(out[:n])


def encrypt_file(path: Path, password: str) -> Path:
    data = path.read_bytes()
    ks = _keystream(password, len(data))
    enc = bytes(a ^ b for a, b in zip(data, ks))
    out = path.with_suffix(path.suffix + ".enc")
    out.write_bytes(enc)
    return out
