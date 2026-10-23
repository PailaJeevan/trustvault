# PROMPTS.md: how AI was used, and where it was wrong

> **Read this first. It is a note to the candidate. Delete this box before submitting.**
>
> Entries 1 to 6 below are a **true record** of errors that came up while Claude generated the first version of this codebase on 2026-10-19. Entries 7 to 11 are from the second iteration on 2026-10-21. Each one was caught by a failing test or a review in that session. They are real, but you did not catch them yourself.
>
> For each entry, before you commit it as yours:
>
> 1. Reproduce it. Revert the fix locally, watch the test fail, then restore the fix.
> 2. Rewrite *"What was done instead"* in your own words, saying what **you** checked.
> 3. Add the commit link.
>
> Then keep adding **new** entries through the week as you change things. The judges compare dates in this file with your commit history. An honest "the AI generated the base, and here is what I verified and changed" scores far better than a file that pretends otherwise. In the interview you will have to explain every entry.

## Reusable context I gave the AI tool every time

Stored in [`docs/AI_CONTEXT.md`](docs/AI_CONTEXT.md) and pasted at the start of every session about this repo:

- Every route taking a document id must call `authorize()` from `app/authz.py` before any read or write. Never query `documents`, `document_versions`, `grants` or `blobs` by a client-supplied id without the authorised document's id in the `WHERE`.
- Role never grants document access.
- Every state change writes an audit record in the same transaction. Refusals are always recorded.
- For every new check, add a test that fails when the check is removed, and add a mutant to `scripts/mutation_check.py`.
- Assume a confident answer about security is wrong until a test shows otherwise.

## Entries

### 1. 2026-10-19: Admin alert query silently ignored the time window (audit trail)

- **Asked:** generate the `/api/admin/alerts` endpoint, listing privileged admin actions (ownership transfers, password resets, role changes) from the last 7 days.
- **Produced:** `WHERE action IN (...) OR (action = 'admin.user_update' AND details LIKE '%"role"%') AND ts >= ?`
- **What was wrong:** SQL `AND` binds tighter than `OR`. The 7-day filter applied only to the role-change branch, so every ownership transfer and password reset *ever* would show as "recent". Denied attempts would have been listed as if they had happened. It looks correct, it runs, and no error appears.
- **What was done instead:** parenthesised the `OR` group and added `outcome = 'success'`.
  - Code: `app/routes/admin.py`, `alerts()`
  - Commit: `LINK`
  - *Your verification:* ______

### 2. 2026-10-19: Refused attempts would vanish from the audit log (audit trail, authorisation)

- **Asked:** make writes check permission inside the locked transaction (to close the check-then-act race), with `authorize()` auditing denials.
- **Produced:** `authorize()` called `audit.append(...)` and then raised. Inside `with transaction(db):`, the raise triggers a `ROLLBACK` that **also rolls back the denial record**. A stranger's attempt to delete or reshare someone else's document would leave no trace. That contradicts "including the attempts that were refused".
- **What was done instead:** when a transaction is open, `_deny()` queues the record with `audit.defer()`, and the `ApiError` handler writes it after the rollback (`audit.flush_deferred()`).
  - Test: `test_refusals_inside_transactions_are_still_recorded`
  - Mutant: `deny-audit`
  - Commit: `LINK`
  - *Your verification:* ______

### 3. 2026-10-19: Test assumed the hash chain detects deleted records; it does not for the newest ones (audit trail)

- **Asked:** write a test that deleting an audit row is detected.
- **Produced:** a test deleting the `document.download` row, expecting `verify_chain()` to fail. It **passed verification**, so the test failed.
- **What was wrong:** the deleted row was the *last* one. Truncating the tail leaves a perfectly consistent shorter chain. The claim "a hash chain proves nothing was deleted" is false for the newest records, and I had been about to write that claim into THREATS.md.
- **What was done instead:**
  - The middle-row test now deletes a middle row.
  - A separate test proves tail truncation is caught by comparing against an export.
  - Added `verify_audit.py --against export.jsonl` and the stdout witness line per record.
  - THREATS AU-2b marks this as *Reduced*, not *Closed*.
  - Commit: `LINK`
  - *Your verification:* ______

### 4. 2026-10-19: Mutation check reported "killed" for the wrong reason (testing authorisation)

- **Asked:** a script that removes each security check and confirms the tests fail.
- **Produced:** 28/28 killed, but two kills were errors, not assertion failures:
  - `directory-role` replaced the decorator with `@login_required`, which is not imported in `users.py`. The `ImportError` failed all 85 tests, and nothing tested viewers listing people.
  - `search-filter` crashed with a `TypeError` (`None["permission"]`) instead of a test detecting that search leaked other people's documents.
- **What was wrong:** a kill caused by a crash proves nothing about test coverage. If someone later made the code more robust, the leak would go undetected.
- **What was done instead:**
  - The mutant now keeps the decorator but adds the `viewer` role.
  - The listing code no longer crashes on a missing grant.
  - Both mutants are now killed by `failures=1` (real assertions), not `errors=`.
  - Commit: `LINK`
  - *Your verification:* ______

### 5. 2026-10-19: Encryption keys silently regenerated per process

- **Asked:** config that requires keys in production and is convenient in development.
- **Produced:** in development, a random key per process. The seed script and the web server therefore used different master keys, so every download failed with `InvalidTag`.
- **What was wrong:** worse than the crash, the pattern hides a real production risk. Any fallback key path means files encrypted under a key nobody saved.
- **What was done instead:**
  - Production refuses to start without both keys.
  - Development persists keys to `instance/dev_keys.json`.
  - Startup refuses if the master and audit keys are equal.
  - Commit: `LINK`
  - *Your verification:* ______

### 6. 2026-10-19: Upload header-injection test tested the framework, not my code

- **Asked:** a test that a hostile filename cannot inject response headers on download.
- **Produced:** a test uploading `a"\r\nSet-Cookie: x=1;.txt`. Werkzeug's multipart parser had already truncated the name at the quote, so the upload was rejected and the download path never ran.
- **What was done instead:** the test now writes the hostile filename straight into the database and asserts the download's `Content-Disposition` stays a single safe header. That exercises *our* sanitising code.
  - Test: `test_header_injection_through_filename_is_impossible`
  - Commit: `LINK`

### 7. 2026-10-21: Demoted owners could still widen access (authorisation)

- **Asked:** probe the v1 build the way a judge would.
- **Found:** after an admin changed Oscar's role from `owner` to `viewer`, Oscar could still `POST` a new edit grant on his own document (HTTP 201).
- **What was wrong:** the v1 rule "role never appears in `authorize()`" was stated as a virtue. It was half right. Role must never *grant* document access, but it is the natural thing that should *take away* the power to hand documents out.
- **What was done instead:**
  - Split the actions into widening (`share`, `restore`) and narrowing (`manage`).
  - Widening also needs the owner role.
  - Upgrading a grant, or extending or removing its expiry, counts as widening. An editor's first draft treated every `PATCH` on a grant as narrowing.
  - Tests: `WideningNeedsOwnerRole`, `ExtendingIsWidening`
  - Mutants: `widen-role`, `widen-detect`
  - Commit: `LINK`

### 8. 2026-10-21: Admin could sabotage the shared demo (access control, operations)

- **Found:** by probing. As `admin@trustvault.test`, `POST /api/admin/users/<olivia>/reset-password` returned 200. One judge could lock every other judge out of the owner account they all share.
- **What was wrong:** v1's `TV_DEMO_MODE` only blocked *self-service* password changes. The admin path was missed.
- **What was done instead:**
  - Demo accounts are protected from password reset, MFA reset, offboarding and MFA enrolment.
  - Reversible actions stay allowed so judges can still test revocation.
  - Test: `DemoProtection`
  - Mutant: `demo-protect`
  - Commit: `LINK`

### 9. 2026-10-21: MFA replay refusal would have been rolled back with no record (audit trail)

- **Asked:** a conditional `UPDATE` so two requests using the same TOTP code cannot both sign in.
- **Produced:** inside `with transaction(db):`, it appended a `denied` audit record and then raised `ApiError`. The raise triggers a ROLLBACK, which removes the audit record.
- **What was wrong:** the same class of bug as entry 2, in new code. A refused replay attempt would leave no trace.
- **What was done instead:** the transaction now records the outcome and commits, and the error is raised *after* the `with` block.
  - Code: `auth_routes.login_mfa`
  - Commit: `LINK`

### 10. 2026-10-21: A wrong MFA code threw the user out of the sign-in flow (UI and auth)

- **Found:** in a browser test, entering a wrong code showed "Your session has ended" and redirected to the login page.
- **What was wrong:** the front end treats every 401 as an expired session, except for the exact path `/api/auth/login`. The new `/api/auth/login/mfa` returns 401 for a wrong code and fell into that rule.
- **What was done instead:** the check became `path.startsWith("/api/auth/login")`, and the browser test now asserts that the error message is the MFA one.
  - Commit: `LINK`

### 11. 2026-10-21: "null" on the alerts page exactly when the audit chain is broken

- **Found:** while reviewing a screenshot of the Account page, which showed a stray "null".
- **What was wrong:** `replaceChildren(cond ? node : null)` renders the text "null". The same pattern was on the Alerts page, inside the branch that only runs when tampering has been detected, so it would have appeared at the worst possible moment.
- **What was done instead:** fixed both places.
  - Commit: `LINK`

### 12. 2026-10-22: A mutant was "killed" by a crash again (testing authorisation)

- **Asked:** add a mutant that removes the admin-only check on the new `/api/admin/stats` route.
- **Produced:** a replacement of `@roles_required("admin")` with `@login_required`, the same mistake as entry 4. `login_required` is not imported in `admin.py`, so all 128 tests "failed" with an import error, and nothing showed that a test actually checks the role.
- **What was done instead:** the mutant now widens the decorator to `roles_required("admin", "owner", "viewer")`. It is killed by exactly one real assertion (`AdminStats.test_admin_only`).
- **Lesson:** I now read the kill line of every new mutant (`failures=` good, `errors=` suspicious).
  - Commit: `LINK`

### 13. 2026-10-22: Dashboard and feed scoping (authorisation, side channels)

- **Asked:** a dashboard with counts, plus a notification feed.
- **Risk checked:** a dashboard is a classic side channel. "Recently changed" or a count can reveal documents the user cannot open, and a feed can reveal who else touched a document that was merely shared with you.
- **What was done:**
  - Every query reuses `VISIBLE_DOCUMENTS_SQL`.
  - The feed is restricted to documents you **own**.
  - Tests prove both; mutants `dashboard-visibility` and `feed-owner` prove the tests depend on the rule.
  - Commit: `LINK`

### 14. 2026-10-22: Readers could download the unredacted original (authorisation design)

- **Asked:** versioning, where "anyone who can read the document can download any version".
- **What was wrong:** that sentence sounds reasonable and is wrong. The most common reason to upload a new version of a confidential file is to *remove* something. With that rule, a reader could fetch v1 by adding `?version=1`. I found it only by attacking the finished system (probe P1); all 130 existing tests passed with the hole open.
- **What was done instead:**
  - A separate action `download_history` for owner and edit level.
  - Readers only see the current version in the list.
  - Test: `RedactionBypass`
  - Mutants: `history-download`, `history-list`
  - Commit: `LINK`

### 15. 2026-10-22: The audit trail let an admin read files they cannot open (audit trail)

- **Asked (originally):** "record the SHA-256 of each upload and download in the audit, so the trail proves exactly which file was taken."
- **What was wrong:** the admin can read the audit but not the files, and that separation is the whole point. A raw SHA-256 of a templated document (a salary letter) is brute-forceable. My probe recovered the salary in 18 guesses from the audit alone. The AI's suggestion and my own review both treated "hash" as "safe to show".
- **What was done instead:**
  - The audit stores `HMAC(audit_key, sha256)`. It still uniquely identifies the file for anyone holding the server key.
  - Test: `HashConfirmation`, which brute-forces both the audit API and the export.
  - Mutant: `content-fp`
  - Commit: `LINK`

### 16. 2026-10-22: HEAD requests wrote false evidence (audit trail)

- **Found:** by probing. Flask silently answers `HEAD` by running the `GET` handler, so a HEAD on the download URL wrote "downloaded" to the audit with no file sent.
- **What was done instead:**
  - All `HEAD` requests to `/api/` are refused before any handler runs.
  - Test: `HeadIsNotADownload`
  - Mutant: `head`
  - Commit: `LINK`

### 17. 2026-10-22: 41 of 69 authorisation checks could be deleted without a test failing (testing authorisation)

- **What I believed:** "56 out of 56 mutants killed" meant the suite tested authorisation.
- **What was wrong:** the 56 mutants were chosen by the same person, and the same AI, that wrote the tests. So they tested what I had thought of. When I wrote `mutation_sweep.py` to delete *every* `authorize()` call and auth decorator automatically, which is what the judges said they would do, only 28 of 69 removals failed a test. Deleting the admin check from **reset password** passed every test.
- **What was done instead:**
  - An access-rule declaration on every route.
  - A route-policy test that enumerates the route map.
  - A test calling every admin route as a non-admin and diffing a database snapshot.
  - Stranger tests for narrowing routes.
  - The sweep re-run until every removal fails a test.
- **Lesson:** hand-picked mutants measure your imagination, not your tests. Generate them.
  - Commit: `LINK`

### 18. 2026-10-23: The new server-side controls made the interface fail silently (authorisation)

- **What I believed:** adding step-up re-authentication and the two-person rule on the server was the whole job, since the server is where enforcement lives.
- **What was wrong:** the browser treated the new `403 reauth_required` like any refusal and showed "not allowed", and an admin's transfer returned `202 pending`, which the UI reported as done. The controls held, but they could not be used, and a reviewer would have read "done" for something that had not happened.
- **What was done instead:**
  - One shared step-up dialog inside `api()`: on `reauth_required` it asks for the password (and code), calls `/api/auth/reauth`, and retries the request once.
  - A `doneToast` that says "Sent for approval" for 202 responses.
  - An Approvals tab where a second administrator approves or rejects.
- **Lesson:** a security control is not finished until the honest path through it works and says truthfully what happened.
  - Commit: `LINK`

---

## Template for your own entries during the week

### N. YYYY-MM-DD: short title (tag: authorisation / audit / upload / other)

- **Asked:** (prompt or a fair summary)
- **Produced:** (what the tool gave you)
- **What was wrong, specifically:**
- **What I did instead:** (with test name and commit link)
