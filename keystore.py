import os
import json
import base64
import uuid
import argparse
import sys
from datetime import datetime, timezone
import getpass

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from argon2 import low_level

# ----- Parametry KDF / szyfrowania -----
ARGON2_TIME = 2           # t
ARGON2_MEMORY = 64 * 1024 # m (KB) -> 64 MB
ARGON2_PARALLELISM = 1    # p
AES_KEY_LEN = 32          # 256 bit

def derive_key(password: bytes, salt: bytes) -> bytes:
    # Argon2id low-level derive
    # zwraca bytes długości AES_KEY_LEN
    return low_level.hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEMORY,
        parallelism=ARGON2_PARALLELISM,
        hash_len=AES_KEY_LEN,
        type=low_level.Type.ID
    )

def generate_rsa_keypair(bits=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem

def encrypt_private(priv_pem: bytes, master_password: str):
    salt = os.urandom(16)
    key = derive_key(master_password.encode('utf-8'), salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, priv_pem, None)  # authenticated
    # zwracamy base64 wartości by łatwo serializować
    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode()
    }

def decrypt_private(enc_obj, master_password: str):
    salt = base64.b64decode(enc_obj["salt"])
    nonce = base64.b64decode(enc_obj["nonce"])
    ct = base64.b64decode(enc_obj["ciphertext"])
    key = derive_key(master_password.encode('utf-8'), salt)
    aesgcm = AESGCM(key)
    priv_pem = aesgcm.decrypt(nonce, ct, None)
    return priv_pem

# ----- przykładowe użycie, zapis do pliku keystore.json -----
def create_entry(label, master_password, bits=2048):
    priv_pem, pub_pem = generate_rsa_keypair(bits=bits)
    enc = encrypt_private(priv_pem, master_password)
    entry = {
        "id": str(uuid.uuid4()),
        "label": label,
        # use timezone-aware UTC timestamp
        "created_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "public_pem": pub_pem.decode(),
        "encrypted_private": enc["ciphertext"],
        "enc_params": {
            "kdf": "argon2id",
            "argon2": {
                "time": ARGON2_TIME,
                "memory_kb": ARGON2_MEMORY,
                "parallelism": ARGON2_PARALLELISM
            },
            "cipher": "aes-256-gcm",
            "nonce": enc["nonce"],
            "salt": enc["salt"]
        }
    }
    return entry


def load_keystore(path: str):
    if not os.path.exists(path):
        return {"version": 1, "entries": []}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _serialize_store(entries) -> bytes:
    return json.dumps({"version": 1, "entries": entries}, ensure_ascii=False).encode("utf-8")


def _deserialize_store(data: bytes):
    return json.loads(data.decode("utf-8"))


def save_keystore_encrypted(path: str, entries, master_password: str):
    """Encrypt and save keystore to path. File format:

    {
      "version":1,
      "encrypted": true,
      "enc_params": {.. salt/nonce/kdf ..},
      "ciphertext": "base64..."
    }
    """
    salt = os.urandom(16)
    key = derive_key(master_password.encode("utf-8"), salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = _serialize_store(entries)
    ct = aes.encrypt(nonce, plaintext, None)
    wrapper = {
        "version": 1,
        "encrypted": True,
        "enc_params": {
            "kdf": "argon2id",
            "argon2": {
                "time": ARGON2_TIME,
                "memory_kb": ARGON2_MEMORY,
                "parallelism": ARGON2_PARALLELISM
            },
            "cipher": "aes-256-gcm",
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode()
        },
        "ciphertext": base64.b64encode(ct).decode()
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(wrapper, f, indent=2, ensure_ascii=False)


def load_keystore_encrypted(path: str, master_password: str):
    with open(path, "r", encoding="utf-8") as f:
        wrapper = json.load(f)
    if not wrapper.get("encrypted"):
        raise ValueError("File is not encrypted")
    enc = wrapper["enc_params"]
    salt = base64.b64decode(enc["salt"])
    nonce = base64.b64decode(enc["nonce"])
    ct = base64.b64decode(wrapper["ciphertext"])
    key = derive_key(master_password.encode("utf-8"), salt)
    aes = AESGCM(key)
    pt = aes.decrypt(nonce, ct, None)
    return _deserialize_store(pt)


def is_store_encrypted(path: str) -> bool:
    if not os.path.exists(path):
        return False
    try:
        with open(path, "r", encoding="utf-8") as f:
            j = json.load(f)
        return bool(j.get("encrypted"))
    except Exception:
        return False


def read_store(path: str, master_password: str | None = None):
    """Read keystore at path. If encrypted, master_password is required.

    Returns dict {version, entries}
    """
    if not os.path.exists(path):
        return {"version": 1, "entries": []}
    if is_store_encrypted(path):
        if master_password is None:
            raise ValueError("Master password required for encrypted keystore")
        return load_keystore_encrypted(path, master_password)
    return load_keystore(path)


def rotate_master(path: str, old_master: str, new_master: str):
    """Odszyfruj store przy pomocy old_master i zapisz ponownie zaszyfrowany new_master."""
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    # read using old master
    data = load_keystore_encrypted(path, old_master)
    entries = data.get("entries", [])
    # write using new master
    save_keystore_encrypted(path, entries, new_master)



def find_entry(entries, entry_id):
    for e in entries:
        if e.get("id") == entry_id:
            return e
    return None


def list_entries(path: str):
    store = load_keystore(path)
    for e in store.get("entries", []):
        print(f"{e.get('id')}\t{e.get('label')}\t{e.get('created_at')}")


def export_public(path: str, entry_id: str, out: str | None = None):
    store = load_keystore(path)
    e = find_entry(store.get("entries", []), entry_id)
    if not e:
        print("Entry not found", file=sys.stderr)
        return 2
    pub = e.get("public_pem")
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(pub)
        print("Wrote public key to", out)
    else:
        print(pub)
    return 0


def decrypt_entry(path: str, entry_id: str, master_password: str, out: str | None = None):
    store = load_keystore(path)
    e = find_entry(store.get("entries", []), entry_id)
    if not e:
        print("Entry not found", file=sys.stderr)
        return 2
    enc_obj = {
        "salt": e["enc_params"]["salt"],
        "nonce": e["enc_params"]["nonce"],
        "ciphertext": e["encrypted_private"]
    }
    try:
        priv = decrypt_private(enc_obj, master_password)
    except Exception as exc:
        print("Decryption failed:", exc, file=sys.stderr)
        return 3
    if out:
        with open(out, "wb") as f:
            f.write(priv)
        print("Wrote private key to", out)
    else:
        print(priv.decode())
    return 0

def save_keystore(path, entries):
    store = {
        "version": 1,
        "entries": entries
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, ensure_ascii=False)

# ---- demo ----
def _cli():
    p = argparse.ArgumentParser(prog="keystore.py")
    p.add_argument("--keystore", default="keystore.json", help="path to keystore.json")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("list", help="List entries")

    c_create = sub.add_parser("create", help="Create a new key entry")
    c_create.add_argument("--label", required=True)
    c_create.add_argument("--bits", type=int, default=2048)

    c_export = sub.add_parser("export-public", help="Export public key for entry id")
    c_export.add_argument("id", help="entry id")
    c_export.add_argument("--out", help="output file for public key")

    c_decrypt = sub.add_parser("decrypt", help="Decrypt private key for entry id")
    c_decrypt.add_argument("id", help="entry id")
    c_decrypt.add_argument("--out", help="output file for private key")

    args = p.parse_args()

    if args.cmd == "list":
        list_entries(args.keystore)
        return 0

    if args.cmd == "create":
        mpw = getpass.getpass("Master password (used to encrypt keystore): ")
        e = create_entry(args.label, mpw, bits=args.bits)
        store = load_keystore(args.keystore)
        store.setdefault("entries", []).append(e)
        # save encrypted keystore
        save_keystore_encrypted(args.keystore, store.get("entries", []), mpw)
        print("Zapisano zaszyfrowany keystore.json z entry id:", e["id"])
        return 0

    if args.cmd == "export-public":
        mpw = None
        if is_store_encrypted(args.keystore):
            mpw = getpass.getpass("Master password: ")
        store = read_store(args.keystore, mpw)
        e = find_entry(store.get("entries", []), args.id)
        if not e:
            print("entry not found", args.id)
            return 2
        pub = e.get("public_pem")
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(pub)
            print("Wrote public key to", args.out)
            return 0
        print(pub)
        return 0

    if args.cmd == "decrypt":
        mpw = None
        if is_store_encrypted(args.keystore):
            mpw = getpass.getpass("Master password: ")
        store = read_store(args.keystore, mpw)
        e = find_entry(store.get("entries", []), args.id)
        if not e:
            print("entry not found", args.id)
            return 2
        enc_obj = {
            "salt": e["enc_params"]["salt"],
            "nonce": e["enc_params"]["nonce"],
            "ciphertext": e["encrypted_private"]
        }
        try:
            priv = decrypt_private(enc_obj, mpw or "")
        except Exception as exc:
            print("decryption failed:", exc)
            return 1
        if args.out:
            with open(args.out, "wb") as f:
                f.write(priv)
            print("Wrote private key to", args.out)
            return 0
        print(priv.decode())
        return 0


if __name__ == "__main__":
    sys.exit(_cli())
