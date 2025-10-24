import os
from pathlib import Path

import pytest

from keystore import (
    create_entry,
    save_keystore_encrypted,
    backup_keystore,
    restore_keystore,
    read_store,
)


def test_backup_and_restore_success(tmp_path: Path):
    ks = tmp_path / "keystore.json"
    bak = tmp_path / "keystore.json.bak"
    master = "s3cr3t-pass"

    # create an entry and save encrypted keystore
    e = create_entry("test-key", master)
    save_keystore_encrypted(str(ks), [e], master)

    assert ks.exists()

    # make a backup
    backup_keystore(str(ks), str(bak))
    assert bak.exists()

    # corrupt the keystore (overwrite with empty store)
    with open(ks, "w", encoding="utf-8") as f:
        f.write("{}")

    # now restore from backup
    restore_keystore(str(bak), str(ks))

    # after restore, we should be able to read the store with the master password
    store = read_store(str(ks), master)
    assert "entries" in store
    assert len(store["entries"]) == 1
    assert store["entries"][0]["label"] == "test-key"


def test_backup_missing_raises(tmp_path: Path):
    ks = tmp_path / "keystore.json"
    bak = tmp_path / "keystore.json.bak"

    # no keystore present -> backup should raise FileNotFoundError
    with pytest.raises(FileNotFoundError):
        backup_keystore(str(ks), str(bak))

    # missing backup on restore should raise
    with pytest.raises(FileNotFoundError):
        restore_keystore(str(bak), str(ks))
