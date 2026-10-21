"""Remove security checks one at a time and prove the test suite notices.

    python -m scripts.mutation_check            # all mutants, 4 in parallel
    python -m scripts.mutation_check owner csrf # only the named ones

For each mutant: copy the repository to a temp directory, make one small edit
that disables one check, run the whole test suite there, and record whether
any test failed ("killed") or everything still passed ("SURVIVED"). A
survivor means a check that no test depends on. Exit code 1 if any survive.

This is exactly what the judges will do by hand; THREATS.md links each
mutant to the threat it stands for.
"""
import os
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# name: (file, exact text to find, replacement, what it simulates)
#   or: ([(file, find, replace), ...], what it simulates)  - for checks with
#       two layers, where removing one alone is (correctly) caught by the other.
MUTANTS = {
    "owner": ("app/authz.py", 'if doc["owner_id"] == user_id:  # AUTHZ-CHECK:owner',
              "if True:", "everyone is treated as the owner"),
    "grant-user": ("app/authz.py", "AND user_id = ?                                        -- AUTHZ-CHECK:grant-user",
                   "AND ? IS NOT NULL", "anyone's grant on a document counts as yours"),
    "revoked": ("app/authz.py", "AND revoked_at IS NULL                                 -- AUTHZ-CHECK:revoked",
                "AND 1 = 1", "revoked grants still work"),
    "expiry": ("app/authz.py", "AND (expires_at IS NULL OR expires_at > ?)             -- AUTHZ-CHECK:expiry",
               "AND (1 = 1 OR expires_at > ?)", "expired grants still work"),
    "action-level": ("app/authz.py", "if level not in ACTION_LEVELS[action]:  # AUTHZ-CHECK:action-level",
                     "if False:", "readers can edit, delete and share"),
    "no-level": ("app/authz.py", "if level is None:  # AUTHZ-CHECK:no-level",
                 "if False:", "no-access check removed (relies on the level check alone)"),
    "deleted": ("app/authz.py", 'elif doc["deleted_at"] is not None:  # AUTHZ-CHECK:deleted',
                "elif False:", "trashed documents stay reachable"),
    "purged": ("app/authz.py", 'if doc["purged_at"] is not None:  # AUTHZ-CHECK:purged',
               "if False:", "purged documents stay reachable"),
    "download-authorize": ("app/routes/documents.py", 'doc = authorize(doc_id, "download")  # <- the authorisation decision',
                           'doc = get_db().execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone(); '
                           'g.doc_level = "read"',
                           "the authorisation line in the download handler is deleted"),
    "edit-authorize": ("app/routes/documents.py", 'doc = authorize(doc_id, "edit")',
                       'doc = authorize(doc_id, "read")', "metadata edit only needs read access"),
    "delete-authorize": ("app/routes/documents.py", 'doc = authorize(doc_id, "delete")',
                         'doc = authorize(doc_id, "edit")', "editors can delete"),
    "share-authorize": ("app/routes/grants.py", 'doc = authorize(doc_id, "share")\n        user = _grantee',
                        'doc = authorize(doc_id, "edit")\n        user = _grantee', "editors can share onwards"),
    "grant-doc": ("app/routes/grants.py", '"SELECT * FROM grants WHERE id = ? AND document_id = ? AND revoked_at IS NULL",',
                  '"SELECT * FROM grants WHERE id = ? AND ? IS NOT NULL AND revoked_at IS NULL",',
                  "grant ids are not tied to the document in the URL"),
    "search-filter": ("app/authz.py", "                      AND gr.user_id = ?\n",
                      "                      AND ? IS NOT NULL\n", "search shows documents shared with anyone"),
    "role": ("app/auth.py", 'if g.user["role"] not in roles:  # AUTHZ-CHECK:role', "if False:",
             "role checks (admin routes, upload) removed"),
    "session-active": ("app/auth.py", 'if not row["is_active"] or', "if False or",
                       "sessions of deactivated users keep working"),
    "session-idle": ("app/auth.py", "or idle_limit <= now", "or False", "idle sessions never expire"),
    "csrf": ("app/auth.py", 'if not constant_time_equal(request.headers.get("X-CSRF-Token")',
             'if False and not constant_time_equal(request.headers.get("X-CSRF-Token")', "CSRF token not checked"),
    "origin": ("app/auth.py", "if origin is not None and not _same_origin(origin):", "if False:",
               "cross-origin requests accepted"),
    "revoke-sessions-on-role": ("app/routes/admin.py", 'if "role" in diff or "is_active" in diff:', "if False:",
                                "role change does not end sessions"),
    "transfer-self": ("app/routes/admin.py", 'if new_owner["id"] == g.user["id"]:  # AUTHZ-CHECK:transfer-self',
                      "if False:", "admin can transfer a document to themselves"),
    "directory-role": ("app/routes/users.py", '@roles_required("owner", "admin")', '@roles_required("owner", "admin", "viewer")',
                       "viewers can list everyone"),
    "deny-audit": ("app/authz.py", "audit.defer(**record)", "pass", "refusals inside transactions are not recorded"),
    "upload-allowlist": ("app/uploads.py", "if ext not in ALLOWED:", "if ext not in ALLOWED and False:",
                         "file type allow-list removed"),
    "upload-magic": ("app/uploads.py", 'if not data.startswith(b"%PDF-"):', "if False:",
                     "PDF content not checked"),
    "download-octet": ("app/routes/documents.py", 'mimetype="application/octet-stream"', 'mimetype=v["mime"]',
                       "downloads served with their own type (may render)"),
    "mass-assignment": ("app/routes/__init__.py", "if unknown:", "if False:", "unknown JSON fields ignored silently"),
    "lockout": ("app/routes/auth_routes.py", 'if user["locked_until"] and user["locked_until"] > now_iso():',
                "if False:", "account lockout not enforced"),
    # --- added in the second iteration ----------------------------------------
    "widen-role": ("app/authz.py", 'if action in WIDENING_ACTIONS and user["role"] != "owner":  # AUTHZ-CHECK:widen-role',
                   "if False:", "demoted owners can still share"),
    "widen-detect": ("app/routes/grants.py", "        if widens:\n", "        if False:\n",
                     "upgrading/extending a grant is not treated as widening"),
    "download-toctou": ("app/routes/documents.py",
                        '    with transaction(db):\n        doc = authorize(doc_id, "download")  # <- the authorisation decision\n',
                        '    doc = authorize(doc_id, "download")\n    with transaction(db):\n',
                        "download checks access BEFORE taking the lock (check-then-act race)"),
    "legal-hold-delete": ("app/routes/documents.py", 'if doc["legal_hold"]:  # AUTHZ-CHECK:legal-hold-delete',
                          "if False:", "documents under legal hold can be deleted"),
    "legal-hold-purge": ("app/retention.py", '"AND purged_at IS NULL AND legal_hold = 0", (cutoff,)',
                         '"AND purged_at IS NULL", (cutoff,)', "retention purges documents under legal hold"),
    "mfa-required": ("app/routes/auth_routes.py", 'if user["mfa_enabled"]:  # AUTHZ-CHECK:mfa-required',
                     "if False:", "password alone signs in an MFA user"),
    "mfa-code": ("app/routes/auth_routes.py", "if step is None:  # AUTHZ-CHECK:mfa-code", "if False:",
                 "wrong MFA codes are not refused / not counted"),
    "mfa-replay": ([("app/routes/auth_routes.py",
                     'step = totp.verify(_user_secret(user), str(data["code"]), user["mfa_last_step"])\n    if step is None:  # AUTHZ-CHECK:mfa-code',
                     'step = totp.verify(_user_secret(user), str(data["code"]), 0)\n    if step is None:  # AUTHZ-CHECK:mfa-code'),
                    ("app/routes/auth_routes.py", "WHERE id = ? AND mfa_last_step < ?\",", "WHERE id = ? AND ? > -1\",")],
                   "a used MFA code can be used again (both layers removed)"),
    "mfa-attempts": ("app/routes/auth_routes.py", ' or ch["attempts"] >= MFA_MAX_ATTEMPTS:', ":",
                     "MFA challenge allows unlimited guesses"),
    "mfa-challenge-expiry": ("app/routes/auth_routes.py", ' or ch["expires_at"] <= now_iso()', "",
                             "MFA challenge never expires"),
    "mfa-disable-code": ("app/routes/auth_routes.py", "if step is None:  # AUTHZ-CHECK:mfa-disable-code",
                         "if False:", "MFA can be switched off without a code"),
    "session-owner": ("app/routes/auth_routes.py", '"DELETE FROM sessions WHERE public_id = ? AND user_id = ?",',
                      '"DELETE FROM sessions WHERE public_id = ? AND ? IS NOT NULL",',
                      "you can end other people's sessions"),
    "offboard-grants": ("app/routes/admin.py", "        for gr in grants:\n", "        for gr in []:\n",
                        "offboarding leaves grants live"),
    "review-authorize": ("app/routes/review.py",
                         'doc = authorize(gr["document_id"], "manage")  # the same decision as a single revoke',
                         'doc = {"id": gr["document_id"]}', "bulk revoke skips the authorisation check"),
    "tag-visibility": ("app/routes/documents.py", 'f"WHERE {VISIBLE_DOCUMENTS_SQL} ORDER BY t.tag LIMIT 200"',
                       'f"WHERE ? IS NOT NULL AND ? IS NOT NULL AND ? IS NOT NULL ORDER BY t.tag LIMIT 200"',
                       "tag list reveals tags of documents you cannot open"),
    "demo-protect": ("app/routes/admin.py", 'if cfg().DEMO_MODE and u["is_demo"]:', "if False:",
                     "admin can lock judges out of shared demo accounts"),
}


def run_mutant(name):
    spec = MUTANTS[name]
    if isinstance(spec[0], list):
        edits, desc = spec
    else:
        edits, desc = [spec[:3]], spec[3]
    work = tempfile.mkdtemp(prefix=f"tv-mut-{name}-")
    try:
        shutil.copytree(ROOT, os.path.join(work, "repo"),
                        ignore=shutil.ignore_patterns(".git", "instance", "__pycache__", "*.db*", ".venv", "venv"))
        repo = os.path.join(work, "repo")
        for path, find, replace in edits:
            target = os.path.join(repo, path)
            with open(target, encoding="utf-8") as f:
                src = f.read()
            if src.count(find) == 0:
                return name, "ERROR", f"text not found in {path} - update MUTANTS", desc
            with open(target, "w", encoding="utf-8") as f:
                f.write(src.replace(find, replace, 1))
        proc = subprocess.run([sys.executable, "-W", "ignore", "-m", "unittest", "discover", "-s", "tests", "-t", "."],
                              cwd=repo, capture_output=True, text=True, timeout=600)
        tail = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else ""
        return name, ("killed" if proc.returncode != 0 else "SURVIVED"), tail, desc
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    names = sys.argv[1:] or list(MUTANTS)
    unknown = [n for n in names if n not in MUTANTS]
    if unknown:
        sys.exit(f"Unknown mutant(s): {unknown}. Known: {', '.join(MUTANTS)}")
    print(f"Running {len(names)} mutant(s)...\n")
    with ThreadPoolExecutor(max_workers=int(os.environ.get("MUTATION_WORKERS", "4"))) as pool:
        results = list(pool.map(run_mutant, names))
    width = max(len(n) for n in names)
    bad = 0
    for name, status, tail, desc in results:
        print(f"{name:<{width}}  {status:<8}  {desc}  [{tail}]")
        bad += status != "killed"
    print(f"\n{len(results) - bad}/{len(results)} mutants killed.")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
