"""Cryptographic helpers: passwords, session tokens, file encryption, HMAC."""
import hashlib
import hmac
import json
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Passwords (scrypt via Werkzeug)
# ---------------------------------------------------------------------------
# A real hash of a random string. Verifying against it when the email does not
# exist makes "unknown user" take as long as "wrong password", so response
# time does not reveal which emails have accounts.
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16), method="scrypt")

MIN_PASSWORD_LENGTH = 12
# scrypt in production. The test harness swaps in a cheap method so the suite
# runs in seconds; nothing outside tests/ changes this.
HASH_METHOD = "scrypt"


def hash_password(password: str) -> str:
    return generate_password_hash(password, method=HASH_METHOD)


def verify_password(password_hash: str | None, password: str) -> bool:
    if password_hash is None:
        check_password_hash(_DUMMY_HASH, password)
        return False
    return check_password_hash(password_hash, password)


# Passwords people actually choose when told "12 characters". Compared after
# lower-casing and dropping everything but letters and digits, so
# "Password@123!" and "password123" are the same entry. Deliberately small and
# offline: no password ever leaves the server to be checked.
_COMMON = {
    "password123", "password1234", "password12345", "passw0rd123", "passwordpassword", "mypassword123",
    "welcome123", "welcome1234", "welcome2024", "welcome2025", "welcome2026", "welcomewelcome",
    "qwerty123456", "qwertyuiop123", "qwertyuiopas", "1qaz2wsx3edc", "1q2w3e4r5t6y", "zaq12wsxcde3",
    "123456789012", "1234567890123", "123456789abc", "abc123456789", "abcdefghijkl", "abcd12345678",
    "iloveyou1234", "letmein12345", "changeme1234", "changeme123", "admin1234567", "administrator",
    "administrator1", "admin@123456", "adminadmin123", "superman1234", "football1234", "baseball1234",
    "sunshine1234", "princess1234", "dragon123456", "monkey123456", "trustno1trustno1", "master123456",
    "india1234567", "india@123456", "bharat123456", "mumbai123456", "delhi1234567", "cricket12345",
    "trustvault123", "trustvault2026", "trustvault1234", "summer202626", "winter2026202", "spring202626",
    "company12345", "companyname1", "secret123456", "secretpassword", "temporary123", "temp12345678",
    "default12345", "guest1234567", "test12345678", "testtest1234", "useruser1234", "login1234567",
}


def _norm(text: str) -> str:
    return "".join(c for c in text.lower() if c.isalnum())


def password_problem(password: str, email: str | None = None, name: str | None = None) -> str | None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if len(password) > 256:
        return "Password is too long."
    flat = _norm(password)
    if flat in _COMMON or flat.rstrip("0123456789") in {_norm(c).rstrip("0123456789") for c in ("password", "welcome", "qwertyuiop", "trustvault", "administrator")}:
        return "That password is on the list of commonly used passwords. Choose something less predictable."
    if len(set(password)) < 5:
        return "Use a password with more variety: at least 5 different characters."
    personal = []
    if email:
        personal.append(_norm(email.split("@")[0]))
    if name:
        personal += [_norm(part) for part in name.split()]
    for p in personal:
        if len(p) >= 3 and p in flat:
            return "Your password must not contain your name or email."
    return None


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------
def new_token() -> str:
    return secrets.token_urlsafe(32)  # 256 bits


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def constant_time_equal(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode(), b.encode())


def new_id() -> str:
    return secrets.token_hex(16)


# ---------------------------------------------------------------------------
# File encryption: envelope encryption with AES-256-GCM.
# ---------------------------------------------------------------------------
def encrypt_blob(master_key: bytes, blob_id: str, plaintext: bytes) -> dict:
    data_key = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    # blob_id is bound in as associated data: ciphertext copied into another
    # row will fail to decrypt.
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, blob_id.encode())
    key_nonce = secrets.token_bytes(12)
    wrapped_key = AESGCM(master_key).encrypt(key_nonce, data_key, b"tv-key:" + blob_id.encode())
    return {"nonce": nonce, "ciphertext": ciphertext, "key_nonce": key_nonce, "wrapped_key": wrapped_key}


def decrypt_blob(master_key: bytes, blob_id: str, row) -> bytes:
    data_key = AESGCM(master_key).decrypt(row["key_nonce"], row["wrapped_key"], b"tv-key:" + blob_id.encode())
    return AESGCM(data_key).decrypt(row["nonce"], row["ciphertext"], blob_id.encode())


def encrypt_secret(master_key: bytes, purpose: str, plaintext: str) -> bytes:
    """Small secrets (MFA seeds). nonce || ciphertext, bound to `purpose`
    (e.g. 'mfa:<user_id>') so a value copied to another user will not decrypt."""
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(master_key).encrypt(nonce, plaintext.encode(), purpose.encode())


def decrypt_secret(master_key: bytes, purpose: str, blob: bytes) -> str:
    return AESGCM(master_key).decrypt(blob[:12], blob[12:], purpose.encode()).decode()


def content_fingerprint(audit_key: bytes, sha256_hex: str) -> str:
    """What the audit trail records about file content.

    Not the raw SHA-256: for a low-entropy document (a salary letter from a
    known template) anyone who can read the audit trail - an administrator -
    could hash every plausible value and confirm the contents without ever
    opening the file. A keyed HMAC still identifies the exact file for anyone
    holding the server key, but cannot be brute-forced from the audit alone."""
    return hmac.new(audit_key, b"content-fp:" + sha256_hex.encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Audit chain
# ---------------------------------------------------------------------------
GENESIS_HASH = "0" * 64


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def audit_hmac(audit_key: bytes, prev_hash: str, record: dict) -> str:
    message = (prev_hash + "|" + canonical_json(record)).encode()
    return hmac.new(audit_key, message, hashlib.sha256).hexdigest()
