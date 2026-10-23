"""Master-key rotation.

Files are encrypted with their own random data key; only that small data key
is encrypted ("wrapped") with the master key. So rotating the master key means
re-wrapping a 32-byte key per file, not re-encrypting the files themselves -
fast, and safe to run on a live database because it is one transaction.
MFA secrets are re-encrypted too. Everything is verified with the NEW key
before the transaction commits; if any check fails, nothing changes.
"""
import hashlib
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import audit
from .db import connect, transaction
from .security import decrypt_secret, encrypt_secret


def key_fingerprint(key: bytes) -> str:
    """Short, non-secret identifier so operators can tell keys apart in logs."""
    return hashlib.sha256(b"tv-key-id:" + key).hexdigest()[:12]


def rotate_master_key(app, new_key: bytes) -> dict:
    old_key = app.config["TV"].MASTER_KEY
    if len(new_key) != 32:
        raise ValueError("The new master key must be 32 bytes.")
    if new_key == old_key or new_key == app.config["TV"].AUDIT_KEY:
        raise ValueError("The new master key must differ from the current master key and the audit key.")
    db = connect(app.config["TV"].DATABASE_PATH)
    try:
        with app.test_request_context("/__key-rotation__"):  # audit.append needs a request-less context
            with transaction(db):
                blobs = db.execute("SELECT id, nonce, ciphertext, key_nonce, wrapped_key FROM blobs").fetchall()
                for b in blobs:
                    aad = b"tv-key:" + b["id"].encode()
                    data_key = AESGCM(old_key).decrypt(b["key_nonce"], b["wrapped_key"], aad)
                    nonce = secrets.token_bytes(12)
                    db.execute("UPDATE blobs SET key_nonce = ?, wrapped_key = ? WHERE id = ?",
                               (nonce, AESGCM(new_key).encrypt(nonce, data_key, aad), b["id"]))
                users = db.execute("SELECT id, mfa_secret_enc FROM users WHERE mfa_secret_enc IS NOT NULL").fetchall()
                for u in users:
                    purpose = f"mfa:{u['id']}"
                    secret = decrypt_secret(old_key, purpose, u["mfa_secret_enc"])
                    db.execute("UPDATE users SET mfa_secret_enc = ? WHERE id = ?",
                               (encrypt_secret(new_key, purpose, secret), u["id"]))
                # Verify every file and secret opens with the NEW key before committing.
                for b in db.execute("SELECT id, nonce, ciphertext, key_nonce, wrapped_key FROM blobs"):
                    data_key = AESGCM(new_key).decrypt(b["key_nonce"], b["wrapped_key"], b"tv-key:" + b["id"].encode())
                    AESGCM(data_key).decrypt(b["nonce"], b["ciphertext"], b["id"].encode())
                for u in db.execute("SELECT id, mfa_secret_enc FROM users WHERE mfa_secret_enc IS NOT NULL"):
                    decrypt_secret(new_key, f"mfa:{u['id']}", u["mfa_secret_enc"])
                result = {"files": len(blobs), "mfa_secrets": len(users),
                          "old_key_id": key_fingerprint(old_key), "new_key_id": key_fingerprint(new_key)}
                audit.append("admin.master_key_rotated", actor_email="system:key-rotation", details=result, db=db)
    finally:
        db.close()
    return result
