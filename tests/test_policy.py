from pocketsoc.policy import write_default_policy


def test_policy_file_created(tmp_path) -> None:
    p = write_default_policy(tmp_path, force=True)
    assert p.exists()
