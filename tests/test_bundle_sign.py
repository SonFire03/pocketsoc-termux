from pathlib import Path

from pocketsoc.bundle_sign import sign_bundle, verify_bundle


def test_bundle_sign_verify(tmp_path) -> None:
    z = tmp_path / 'a.zip'
    z.write_bytes(b'zipdata')
    sign_bundle(z, tmp_path)
    assert verify_bundle(z, tmp_path)
