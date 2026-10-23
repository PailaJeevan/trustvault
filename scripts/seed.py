"""Create demo users and documents.

    python -m scripts.seed            # seed an empty database
    python -m scripts.seed --reset    # delete the database file first (demo resets)

Passwords for the demo accounts are printed in README.md. They are public on
purpose (the judges need them); the accounts are marked is_demo so that, with
TV_DEMO_MODE=1, nobody can change their password and lock the others out.
"""
import hashlib
import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402
from app import audit  # noqa: E402
from datetime import timedelta  # noqa: E402

from app.db import get_db, iso, now_iso, transaction, utcnow  # noqa: E402
from app.security import encrypt_blob, encrypt_secret, hash_password, new_id  # noqa: E402

DEMO_USERS = [
    # email,                    name,              role,     password
    ("admin@trustvault.test",   "Asha Admin",      "admin",  "Admin-Demo-2026!"),
    # A second administrator: the two-person rule needs one to request and
    # another to approve password resets, MFA resets, transfers and promotions.
    ("admin2@trustvault.test",  "Arjun Admin",     "admin",  "Arjun-Demo-2026!"),
    ("olivia@trustvault.test",  "Olivia Owner",    "owner",  "Olivia-Demo-2026!"),
    ("oscar@trustvault.test",   "Oscar Owner",     "owner",  "Oscar-Demo-2026!"),
    ("vera@trustvault.test",    "Vera Viewer",     "viewer", "Vera-Demo-2026!"),
    ("victor@trustvault.test",  "Victor Viewer",   "viewer", "Victor-Demo-2026!"),
    ("ext@partner.test",        "Pat Partner (external)", "viewer", "Partner-Demo-2026!"),
    ("maya@trustvault.test",    "Maya MFA Owner",  "owner",  "Maya-Demo-2026!"),
]

# Maya has two-step sign-in turned on. This setup key is PUBLIC on purpose so
# judges can add it to an authenticator app (or run `oathtool --totp -b KEY`)
# and try the MFA flow. Never publish a real user's key.
DEMO_MFA_USER = "maya"
DEMO_MFA_SECRET = "JBSWY3DPEHPK3PXPTRUSTVAULTDEMO22"

DEMO_TAGS = {
    "Salary letter - Vera": ["payroll", "2026"],
    "Salary letter - Victor": ["payroll", "2026"],
    "Q3 board financials": ["board", "quarterly"],
    "Master services agreement - Partner": ["contract", "external"],
    "Bridge drawings rev B": ["span-3", "structural"],
    "Site photo - span 3": ["span-3", "photo"],
}


def _docx(text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        z.writestr("word/document.xml", f'<?xml version="1.0"?><w:document xmlns:w="x"><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>')
    return buf.getvalue()


def _png(w: int = 480, h: int = 300) -> bytes:
    """A small generated 'site photo' (a sky-to-ground gradient with a bridge
    deck), so the demo has an image to open in the viewer. Standard library only."""
    import struct
    import zlib
    rows = []
    for y in range(h):
        row = bytearray([0])
        for x in range(w):
            if 170 <= y <= 182 or (y > 182 and (x % 120) in range(56, 64)):
                px = (70, 78, 86)                      # deck and piers
            elif y < 182:
                t = y / 182
                px = (int(150 + 70 * t), int(190 + 40 * t), int(225 + 20 * t))   # sky
            else:
                t = (y - 182) / (h - 182)
                px = (int(46 + 30 * t), int(92 + 20 * t), int(110 - 30 * t))     # water
            row += bytes(px)
        rows.append(bytes(row))
    raw = zlib.compress(b"".join(rows), 9)
    chunk = lambda tag, data: struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", raw) + chunk(b"IEND", b""))


def _pdf(text: str) -> bytes:
    return (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Count 0>>endobj\n"
            b"% " + text.encode() + b"\ntrailer<</Root 1 0 R>>\n%%EOF\n")


DEMO_DOCS = [
    # owner,   title,                                category,  filename,                 content
    ("olivia", "Salary letter - Vera",               "HR",      "salary-vera.pdf",        _pdf("CONFIDENTIAL salary letter for Vera Viewer: INR 18,00,000")),
    ("olivia", "Salary letter - Victor",             "HR",      "salary-victor.pdf",      _pdf("CONFIDENTIAL salary letter for Victor Viewer: INR 21,00,000")),
    ("olivia", "Q3 board financials",                "Finance", "q3-financials.csv",      b"quarter,revenue,cost\nQ3,4200000,3100000\n"),
    ("olivia", "Master services agreement - Partner","Legal",   "msa-partner.docx",       _docx("MSA between TrustVault Demo Co and Partner Ltd")),
    ("oscar",  "Bridge drawings rev B",              "Engineering", "bridge-rev-b.txt",   b"Load calculations for span 3. Internal only.\n"),
    ("oscar",  "Statutory audit working papers",     "Audit",   "audit-papers.md",        b"# FY26 audit\n\nSample of 40 invoices tested.\n"),
    ("oscar",  "Site photo - span 3",                "Engineering", "span-3.png",          _png()),
    ("oscar",  "Oscar's private notes",              "General", "notes.txt",              b"Nobody else should be able to read this.\n"),
    ("maya",   "Board minutes - October",            "Legal",   "board-minutes.md",       b"# Board minutes\n\nOnly Maya can read this. Her account has two-step sign-in.\n"),
]

DEMO_GRANTS = [
    # doc title,                         grantee,   permission, access ends in N days (None = never)
    ("Salary letter - Vera",             "vera",    "read",  90),
    ("Salary letter - Victor",           "victor",  "read",  None),
    ("Q3 board financials",              "oscar",   "read",  30),
    ("Q3 board financials",              "vera",    "edit",  None),
    ("Master services agreement - Partner", "ext",  "read",  5),
    ("Bridge drawings rev B",            "victor",  "edit",  60),
    ("Site photo - span 3",              "victor",  "read",  60),
    ("Statutory audit working papers",   "vera",    "read",  14),
]


def seed(app):
    cfg = app.config["TV"]
    if cfg.ENV == "production" and not cfg.DEMO_MODE:  # AUTHZ-CHECK:seed-prod
        raise SystemExit("Refusing to seed: the demo accounts have PUBLIC passwords. "
                         "Set TV_DEMO_MODE=1 only on a demo deployment.")
    with app.app_context():
        db = get_db()
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            print("Database already has users; not seeding. Use --reset to start over.")
            return
        cfg = app.config["TV"]
        ids = {}
        now = now_iso()
        with transaction(db):
            for email, name, role, pw in DEMO_USERS:
                uid = new_id()
                ids[email.split("@")[0]] = uid
                db.execute("INSERT INTO users (id, email, name, role, password_hash, is_demo, created_at, updated_at) "
                           "VALUES (?, ?, ?, ?, ?, 1, ?, ?)", (uid, email, name, role, hash_password(pw), now, now))
                audit.append("admin.user_create", actor_email="system:seed", target_user_id=uid,
                             details={"email": email, "role": role}, db=db)
            mfa_uid = ids[DEMO_MFA_USER]
            db.execute("UPDATE users SET mfa_enabled = 1, mfa_secret_enc = ? WHERE id = ?",
                       (encrypt_secret(cfg.MASTER_KEY, f"mfa:{mfa_uid}", DEMO_MFA_SECRET), mfa_uid))
            doc_ids = {}
            for owner, title, category, filename, content in DEMO_DOCS:
                did, bid = new_id(), new_id()
                doc_ids[title] = did
                enc = encrypt_blob(cfg.MASTER_KEY, bid, content)
                db.execute("INSERT INTO documents (id, title, description, category, owner_id, created_at, updated_at) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?)", (did, title, "Demo document", category, ids[owner], now, now))
                db.execute("INSERT INTO blobs (id, nonce, ciphertext, key_nonce, wrapped_key) VALUES (?, ?, ?, ?, ?)",
                           (bid, enc["nonce"], enc["ciphertext"], enc["key_nonce"], enc["wrapped_key"]))
                db.execute("INSERT INTO document_versions (id, document_id, version_no, blob_id, filename, mime, "
                           "size_bytes, sha256, uploaded_by, created_at) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?)",
                           (new_id(), did, bid, filename, "application/octet-stream", len(content),
                            hashlib.sha256(content).hexdigest(), ids[owner], now))
                audit.append("document.upload", actor_email="system:seed", document_id=did,
                             details={"title": title, "owner": owner}, db=db)
            for title, tags in DEMO_TAGS.items():
                db.executemany("INSERT INTO document_tags (document_id, tag) VALUES (?, ?)",
                               [(doc_ids[title], t) for t in tags])
            for title, grantee, perm, days in DEMO_GRANTS:
                did = doc_ids[title]
                owner = next(o for o, t, *_ in DEMO_DOCS if t == title)
                expires = iso(utcnow() + timedelta(days=days)) if days else None
                db.execute("INSERT INTO grants (id, document_id, user_id, permission, granted_by, created_at, expires_at) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?)", (new_id(), did, ids[grantee], perm, ids[owner], now, expires))
                audit.append("permission.grant", actor_email="system:seed", document_id=did,
                             target_user_id=ids[grantee], details={"permission": perm, "expires_at": expires}, db=db)
        print(f"Seeded {len(DEMO_USERS)} users, {len(DEMO_DOCS)} documents, {len(DEMO_GRANTS)} grants.")


if __name__ == "__main__":
    app = create_app()
    if "--reset" in sys.argv:
        path = app.config["TV"].DATABASE_PATH
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(path + suffix):
                os.remove(path + suffix)
        app = create_app()
    seed(app)
