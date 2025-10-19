import os

from keystore import (
    create_entry,
    save_keystore_encrypted,
    load_keystore_encrypted,
    rotate_master,
)


def test_rotate_master(tmp_path):
    mpw_old = "old-pass"
    mpw_new = "new-pass"
    e = create_entry("rkey", mpw_old, bits=1024)
    ks = tmp_path / "ks_enc.json"
    # save encrypted with old master
    save_keystore_encrypted(str(ks), [e], mpw_old)

    # ensure we can load with old master
    store = load_keystore_encrypted(str(ks), mpw_old)
    assert store["entries"][0]["id"] == e["id"]

    # rotate master
    rotate_master(str(ks), mpw_old, mpw_new)

    # should fail with old master now (decryption should raise)
    try:
        load_keystore_encrypted(str(ks), mpw_old)
        assert False, "old master should not decrypt after rotation"
    except Exception:
        pass

    # should succeed with new master
    store2 = load_keystore_encrypted(str(ks), mpw_new)
    assert store2["entries"][0]["id"] == e["id"]
