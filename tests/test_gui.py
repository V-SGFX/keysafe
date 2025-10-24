import os
import shutil

from gui import app
from keystore import load_keystore_encrypted, restore_backup


def test_gui_create_and_backup(tmp_path):
    # run the Flask test client in a temporary directory so tests don't touch repo files
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        client = app.test_client()
        # ensure clean
        if os.path.exists("keystore.json"):
            os.remove("keystore.json")

        # create an entry via the GUI POST
        resp = client.post(
            "/create",
            data={"label": "gui-test", "bits": "1024", "master": "testpass"},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303)

        # decrypt and verify one entry
        data = load_keystore_encrypted("keystore.json", "testpass")
        assert len(data.get("entries", [])) == 1

        # create a backup and remove the original file
        shutil.copy("keystore.json", "keystore.json.bak")
        os.remove("keystore.json")
        assert not os.path.exists("keystore.json")

        # restore from backup
        restored = restore_backup("keystore.json")
        assert restored is True
        assert os.path.exists("keystore.json")

        # verify restored file decrypts correctly
        data2 = load_keystore_encrypted("keystore.json", "testpass")
        assert len(data2.get("entries", [])) == 1
        assert data2["entries"][0]["label"] == "gui-test"
    finally:
        os.chdir(cwd)
