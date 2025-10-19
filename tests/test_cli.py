import os

from keystore import create_entry, save_keystore, export_public, list_entries


def test_export_public_writes_file(tmp_path):
    mpw = "cli-test"
    e = create_entry("cli-key", mpw, bits=1024)
    ks = tmp_path / "ks.json"
    save_keystore(str(ks), [e])
    out = tmp_path / "pub.pem"
    rc = export_public(str(ks), e["id"], str(out))
    assert rc == 0
    data = out.read_text(encoding="utf-8")
    assert data.startswith("-----BEGIN PUBLIC KEY-----")


def test_list_entries_prints(tmp_path, capsys):
    mpw = "cli-test2"
    e = create_entry("cli-key-2", mpw, bits=1024)
    ks = tmp_path / "ks2.json"
    save_keystore(str(ks), [e])
    list_entries(str(ks))
    captured = capsys.readouterr()
    assert e["id"] in captured.out
    assert "cli-key-2" in captured.out
