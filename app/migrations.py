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
    3: """
        -- When the owner last opened their activity feed (for the unread count).
        ALTER TABLE users ADD COLUMN feed_seen_at TEXT;
        CREATE INDEX idx_audit_ts_outcome ON audit_log(ts, outcome);
    """,
    4: """
        -- Step-up authentication: when this session last proved the password.
        ALTER TABLE sessions ADD COLUMN reauth_at TEXT;

        -- Sign-in throttling shared by every worker and surviving restarts
        -- (it used to live in one process's memory).
        CREATE TABLE login_attempts (
            key  TEXT NOT NULL,
            ts   TEXT NOT NULL
        );
        CREATE INDEX idx_login_attempts_key ON login_attempts(key, ts);
        CREATE INDEX idx_login_attempts_ts ON login_attempts(ts);

        -- Two-person rule: the most dangerous admin powers are requested by one
        -- administrator and carried out only when a different one approves.
        CREATE TABLE admin_requests (
            id              TEXT PRIMARY KEY,
            action          TEXT NOT NULL CHECK (action IN
                                ('reset_password', 'reset_mfa', 'transfer_ownership', 'promote_admin')),
            target_user_id  TEXT REFERENCES users(id),
            document_id     TEXT REFERENCES documents(id),
            payload         TEXT NOT NULL DEFAULT '{}',
            reason          TEXT NOT NULL DEFAULT '',
            requested_by    TEXT NOT NULL REFERENCES users(id),
            requested_at    TEXT NOT NULL,
            expires_at      TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN
                                ('pending', 'approved', 'rejected', 'cancelled', 'expired', 'failed')),
            decided_by      TEXT REFERENCES users(id),
            decided_at      TEXT,
            outcome         TEXT
        );
        CREATE INDEX idx_admin_requests_status ON admin_requests(status, requested_at);
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
