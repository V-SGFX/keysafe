import os
import json
import tempfile

from keystore import create_entry, decrypt_private, encrypt_private, save_keystore, load_keystore


def test_create_and_decrypt_roundtrip(tmp_path):
    mpw = "test-master"
    e = create_entry("t1", mpw, bits=1024)
    # save and load
    p = tmp_path / "ks.json"
    save_keystore(str(p), [e])
    store = load_keystore(str(p))
    assert store["entries"][0]["id"] == e["id"]

    enc_obj = {
        "salt": e["enc_params"]["salt"],
        "nonce": e["enc_params"]["nonce"],
        "ciphertext": e["encrypted_private"]
    }
    priv = decrypt_private(enc_obj, mpw)
    assert priv.startswith(b"-----BEGIN")


def test_encrypt_private_returns_base64():
    mpw = "x"
    priv, pub = None, None
    # generate small key via create_entry
    e = create_entry("t2", mpw, bits=1024)
    assert isinstance(e["encrypted_private"], str)
    assert isinstance(e["enc_params"]["salt"], str)
    assert isinstance(e["enc_params"]["nonce"], str)
