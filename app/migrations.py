"""Schema migrations.

`schema.sql` is version 1. Each entry below upgrades the schema by one
version and is applied exactly once, in order, tracked by SQLite's
`PRAGMA user_version`. A database created before a feature existed is
upgraded in place on the next start - nothing is dropped, nothing re-seeded.

Never edit a migration that has shipped; add a new one.
"""

MIGRATIONS = {
    2: """
        -- Multi-factor authentication (TOTP). The secret is encrypted with the
        -- master key, like file content, so a DB copy does not reveal it.
        ALTER TABLE users ADD COLUMN mfa_secret_enc BLOB;
        ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0 CHECK (mfa_enabled IN (0, 1));
        ALTER TABLE users ADD COLUMN mfa_last_step INTEGER NOT NULL DEFAULT 0;   -- replay protection

        CREATE TABLE mfa_challenges (
            token_hash   TEXT PRIMARY KEY,
            user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at   TEXT NOT NULL,
            expires_at   TEXT NOT NULL,
            attempts     INTEGER NOT NULL DEFAULT 0
        );

        -- A public, non-secret handle for each session so a user can list and
        -- end their own sessions without ever seeing a token or its hash.
        ALTER TABLE sessions ADD COLUMN public_id TEXT;
        UPDATE sessions SET public_id = lower(hex(randomblob(8))) WHERE public_id IS NULL;
        CREATE UNIQUE INDEX uq_sessions_public_id ON sessions(public_id);

        -- Legal hold: a document under hold cannot be deleted or purged.
        ALTER TABLE documents ADD COLUMN legal_hold INTEGER NOT NULL DEFAULT 0 CHECK (legal_hold IN (0, 1));
        ALTER TABLE documents ADD COLUMN legal_hold_reason TEXT;
        ALTER TABLE documents ADD COLUMN legal_hold_by TEXT REFERENCES users(id);
        ALTER TABLE documents ADD COLUMN legal_hold_at TEXT;

        -- Tags, for organising. Labels only: a tag never confers access.
        CREATE TABLE document_tags (
            document_id  TEXT NOT NULL REFERENCES documents(id),
            tag          TEXT NOT NULL,
            PRIMARY KEY (document_id, tag)
        );
        CREATE INDEX idx_document_tags_tag ON document_tags(tag);
    """,
}

LATEST = max(MIGRATIONS)


def migrate(db) -> list[int]:
    """Apply pending migrations. Each runs in its own exclusive transaction,
    and the version is re-read inside it, so two workers starting at once
    cannot both apply the same migration."""
    applied = []
    for version in sorted(MIGRATIONS):
        db.execute("BEGIN EXCLUSIVE")
        try:
            current = db.execute("PRAGMA user_version").fetchone()[0]
            if current >= version:
                db.execute("COMMIT")
                continue
            for statement in _statements(MIGRATIONS[version]):
                db.execute(statement)
            db.execute(f"PRAGMA user_version = {int(version)}")
            db.execute("COMMIT")
            applied.append(version)
        except BaseException:
            db.execute("ROLLBACK")
            raise
    return applied


def _statements(script: str):
    """Split a migration into statements (none of ours contain ';' in strings
    or trigger bodies; keep it that way or extend this)."""
    lines = [ln for ln in script.splitlines() if not ln.strip().startswith("--")]
    for stmt in "\n".join(lines).split(";"):
        if stmt.strip():
            yield stmt.strip()
