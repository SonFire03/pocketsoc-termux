from pocketsoc.exporters import export_siem


def test_exporters_create_file(tmp_path) -> None:
    out = export_siem(tmp_path, "syslog-json")
    assert out.exists()
