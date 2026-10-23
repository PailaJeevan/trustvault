# PROMPTS.md: how AI was used, and where it was wrong

TrustVault was built with an AI coding assistant (Claude, by Anthropic). I directed the work, ran the code, and reviewed and tested what it produced. This file records where the AI's output was wrong, how each problem was caught, and what changed.

**How to read the dates and links.** Entries 1 to 18 come from the AI-assisted build sessions on 2026-10-19 to 2026-10-23. Most were caught by failing tests, by probing the running system, or by reviewing screenshots. I put the code on GitHub on 2026-10-22 and 2026-10-23 as file uploads, so several fixes arrived together. Each commit link points to the commit where that fix **first appears in this repository**, not to a commit made on the day of the entry. Entry 19 onwards come from my own deployment and checking of the live site, and each one links to the commit that made the change.

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
  - Commit (first in repository): [f4e7e22](https://github.com/PailaJeevan/trustvault/commit/f4e7e22)

### 2. 2026-10-19: Refused attempts would vanish from the audit log (audit trail, authorisation)

- **Asked:** make writes check permission inside the locked transaction (to close the check-then-act race), with `authorize()` auditing denials.
- **Produced:** `authorize()` called `audit.append(...)` and then raised. Inside `with transaction(db):`, the raise triggers a `ROLLBACK` that **also rolls back the denial record**. A stranger's attempt to delete or reshare someone else's document would leave no trace. That contradicts "including the attempts that were refused".
- **What was done instead:** when a transaction is open, `_deny()` queues the record with `audit.defer()`, and the `ApiError` handler writes it after the rollback (`audit.flush_deferred()`).
  - Test: `test_refusals_inside_transactions_are_still_recorded`
  - Mutant: `deny-audit`
  - Commit (first in repository): [f4e7e22](https://github.com/PailaJeevan/trustvault/commit/f4e7e22)

### 3. 2026-10-19: Test assumed the hash chain detects deleted records; it does not for the newest ones (audit trail)

- **Asked:** write a test that deleting an audit row is detected.
- **Produced:** a test deleting the `document.download` row, expecting `verify_chain()` to fail. It **passed verification**, so the test failed.
- **What was wrong:** the deleted row was the *last* one. Truncating the tail leaves a perfectly consistent shorter chain. The claim "a hash chain proves nothing was deleted" is false for the newest records, and I had been about to write that claim into THREATS.md.
- **What was done instead:**
  - The middle-row test now deletes a middle row.
  - A separate test proves tail truncation is caught by comparing against an export.
  - Added `verify_audit.py --against export.jsonl` and the stdout witness line per record.
  - THREATS AU-2b marks this as *Reduced*, not *Closed*.
  - Commit (first in repository): [e364ac6](https://github.com/PailaJeevan/trustvault/commit/e364ac6)

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
  - Commit (first in repository): [e364ac6](https://github.com/PailaJeevan/trustvault/commit/e364ac6)

### 5. 2026-10-19: Encryption keys silently regenerated per process

- **Asked:** config that requires keys in production and is convenient in development.
- **Produced:** in development, a random key per process. The seed script and the web server therefore used different master keys, so every download failed with `InvalidTag`.
- **What was wrong:** worse than the crash, the pattern hides a real production risk. Any fallback key path means files encrypted under a key nobody saved.
- **What was done instead:**
  - Production refuses to start without both keys.
  - Development persists keys to `instance/dev_keys.json`.
  - Startup refuses if the master and audit keys are equal.
  - Commit (first in repository): [f4e7e22](https://github.com/PailaJeevan/trustvault/commit/f4e7e22)

### 6. 2026-10-19: Upload header-injection test tested the framework, not my code

- **Asked:** a test that a hostile filename cannot inject response headers on download.
- **Produced:** a test uploading `a"\r\nSet-Cookie: x=1;.txt`. Werkzeug's multipart parser had already truncated the name at the quote, so the upload was rejected and the download path never ran.
- **What was done instead:** the test now writes the hostile filename straight into the database and asserts the download's `Content-Disposition` stays a single safe header. That exercises *our* sanitising code.
  - Test: `test_header_injection_through_filename_is_impossible`
  - Commit (first in repository): [817fd25](https://github.com/PailaJeevan/trustvault/commit/817fd25)

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
  - Commit (first in repository): [f4e7e22](https://github.com/PailaJeevan/trustvault/commit/f4e7e22)

### 8. 2026-10-21: Admin could sabotage the shared demo (access control, operations)

- **Found:** by probing. As `admin@trustvault.test`, `POST /api/admin/users/<olivia>/reset-password` returned 200. One judge could lock every other judge out of the owner account they all share.
- **What was wrong:** v1's `TV_DEMO_MODE` only blocked *self-service* password changes. The admin path was missed.
- **What was done instead:**
  - Demo accounts are protected from password reset, MFA reset, offboarding and MFA enrolment.
  - Reversible actions stay allowed so judges can still test revocation.
  - Test: `DemoProtection`
  - Mutant: `demo-protect`
  - Commit (first in repository): [817fd25](https://github.com/PailaJeevan/trustvault/commit/817fd25)

### 9. 2026-10-21: MFA replay refusal would have been rolled back with no record (audit trail)

- **Asked:** a conditional `UPDATE` so two requests using the same TOTP code cannot both sign in.
- **Produced:** inside `with transaction(db):`, it appended a `denied` audit record and then raised `ApiError`. The raise triggers a ROLLBACK, which removes the audit record.
- **What was wrong:** the same class of bug as entry 2, in new code. A refused replay attempt would leave no trace.
- **What was done instead:** the transaction now records the outcome and commits, and the error is raised *after* the `with` block.
  - Code: `auth_routes.login_mfa`
  - Commit (first in repository): [f4e7e22](https://github.com/PailaJeevan/trustvault/commit/f4e7e22)

### 10. 2026-10-21: A wrong MFA code threw the user out of the sign-in flow (UI and auth)

- **Found:** in a browser test, entering a wrong code showed "Your session has ended" and redirected to the login page.
- **What was wrong:** the front end treats every 401 as an expired session, except for the exact path `/api/auth/login`. The new `/api/auth/login/mfa` returns 401 for a wrong code and fell into that rule.
- **What was done instead:** the check became `path.startsWith("/api/auth/login")`, and the browser test now asserts that the error message is the MFA one.
  - Commit (first in repository): [06973bc](https://github.com/PailaJeevan/trustvault/commit/06973bc)

### 11. 2026-10-21: "null" on the alerts page exactly when the audit chain is broken

- **Found:** while reviewing a screenshot of the Account page, which showed a stray "null".
- **What was wrong:** `replaceChildren(cond ? node : null)` renders the text "null". The same pattern was on the Alerts page, inside the branch that only runs when tampering has been detected, so it would have appeared at the worst possible moment.
- **What was done instead:** fixed both places.
  - Commit (first in repository): [06973bc](https://github.com/PailaJeevan/trustvault/commit/06973bc)

### 12. 2026-10-22: A mutant was "killed" by a crash again (testing authorisation)

- **Asked:** add a mutant that removes the admin-only check on the new `/api/admin/stats` route.
- **Produced:** a replacement of `@roles_required("admin")` with `@login_required`, the same mistake as entry 4. `login_required` is not imported in `admin.py`, so all 128 tests "failed" with an import error, and nothing showed that a test actually checks the role.
- **What was done instead:** the mutant now widens the decorator to `roles_required("admin", "owner", "viewer")`. It is killed by exactly one real assertion (`AdminStats.test_admin_only`).
- **Lesson:** I now read the kill line of every new mutant (`failures=` good, `errors=` suspicious).
  - Commit (first in repository): [3ebaa92](https://github.com/PailaJeevan/trustvault/commit/3ebaa92)

### 13. 2026-10-22: Dashboard and feed scoping (authorisation, side channels)

- **Asked:** a dashboard with counts, plus a notification feed.
- **Risk checked:** a dashboard is a classic side channel. "Recently changed" or a count can reveal documents the user cannot open, and a feed can reveal who else touched a document that was merely shared with you.
- **What was done:**
  - Every query reuses `VISIBLE_DOCUMENTS_SQL`.
  - The feed is restricted to documents you **own**.
  - Tests prove both; mutants `dashboard-visibility` and `feed-owner` prove the tests depend on the rule.
  - Commit (first in repository): [c62a39f](https://github.com/PailaJeevan/trustvault/commit/c62a39f)

### 14. 2026-10-22: Readers could download the unredacted original (authorisation design)

- **Asked:** versioning, where "anyone who can read the document can download any version".
- **What was wrong:** that sentence sounds reasonable and is wrong. The most common reason to upload a new version of a confidential file is to *remove* something. With that rule, a reader could fetch v1 by adding `?version=1`. I found it only by attacking the finished system (probe P1); all 130 existing tests passed with the hole open.
- **What was done instead:**
  - A separate action `download_history` for owner and edit level.
  - Readers only see the current version in the list.
  - Test: `RedactionBypass`
  - Mutants: `history-download`, `history-list`
  - Commit (first in repository): [3ebaa92](https://github.com/PailaJeevan/trustvault/commit/3ebaa92)

### 15. 2026-10-22: The audit trail let an admin read files they cannot open (audit trail)

- **Asked (originally):** "record the SHA-256 of each upload and download in the audit, so the trail proves exactly which file was taken."
- **What was wrong:** the admin can read the audit but not the files, and that separation is the whole point. A raw SHA-256 of a templated document (a salary letter) is brute-forceable. My probe recovered the salary in 18 guesses from the audit alone. The AI's suggestion and my own review both treated "hash" as "safe to show".
- **What was done instead:**
  - The audit stores `HMAC(audit_key, sha256)`. It still uniquely identifies the file for anyone holding the server key.
  - Test: `HashConfirmation`, which brute-forces both the audit API and the export.
  - Mutant: `content-fp`
  - Commit (first in repository): [3ebaa92](https://github.com/PailaJeevan/trustvault/commit/3ebaa92)

### 16. 2026-10-22: HEAD requests wrote false evidence (audit trail)

- **Found:** by probing. Flask silently answers `HEAD` by running the `GET` handler, so a HEAD on the download URL wrote "downloaded" to the audit with no file sent.
- **What was done instead:**
  - All `HEAD` requests to `/api/` are refused before any handler runs.
  - Test: `HeadIsNotADownload`
  - Mutant: `head`
  - Commit (first in repository): [3ebaa92](https://github.com/PailaJeevan/trustvault/commit/3ebaa92)

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
  - Commit (first in repository): [c62a39f](https://github.com/PailaJeevan/trustvault/commit/c62a39f)

### 18. 2026-10-23: The new server-side controls made the interface fail silently (authorisation)

- **What I believed:** adding step-up re-authentication and the two-person rule on the server was the whole job, since the server is where enforcement lives.
- **What was wrong:** the browser treated the new `403 reauth_required` like any refusal and showed "not allowed", and an admin's transfer returned `202 pending`, which the UI reported as done. The controls held, but they could not be used, and a reviewer would have read "done" for something that had not happened.
- **What was done instead:**
  - One shared step-up dialog inside `api()`: on `reauth_required` it asks for the password (and code), calls `/api/auth/reauth`, and retries the request once.
  - A `doneToast` that says "Sent for approval" for 202 responses.
  - An Approvals tab where a second administrator approves or rejects.
- **Lesson:** a security control is not finished until the honest path through it works and says truthfully what happened.
  - Commit (first in repository): [06973bc](https://github.com/PailaJeevan/trustvault/commit/06973bc)

### 19. 2026-10-24: Behind Render's proxy, the audit trail recorded Render's own address instead of the visitor's (audit trail)

- **Found:** by running `scripts/check_live.py` against the deployed site. The check *"audit records real client IPs"* failed with `got 10.27.188.5`, a private address inside Render's network.
- **What was wrong:** the app trusted one proxy hop (`TV_TRUSTED_PROXIES=1`), which is right for PythonAnywhere. Render adds its own internal address to the end of `X-Forwarded-For`, so every audit record, including refused attempts, named Render's load balancer instead of the person. The brief asks us to *prove who* reached a document, and a wrong IP weakens that proof.
- **What I did instead:**
  - The client address now uses its own setting, `TV_FORWARDED_FOR_HOPS=2` in `render.yaml`. The scheme and host still trust exactly one hop, so the CSRF Origin check keeps working.
  - Verified that a forged `X-Forwarded-For` sent by an attacker is still ignored: the recorded address is the one Render saw, not the one the client claimed.
  - Commits: [249c565](https://github.com/PailaJeevan/trustvault/commit/249c565) (app), [f6efdf8](https://github.com/PailaJeevan/trustvault/commit/f6efdf8) (render.yaml)

### 20. 2026-10-24: The live checker reported six false failures on Render (testing)

- **Found:** the same run showed the security headers and the HTTPS redirect as failing. Printing the raw response showed the headers *were* present: `x-frame-options: DENY`, `strict-transport-security: max-age=31536000; includeSubDomains`, and so on.
- **What was wrong:** the checker was wrong, not the site, in two ways:
  - It copied the headers into a plain `dict`, which made the lookup case-sensitive. Render's network (Cloudflare) sends header names in lower case, which HTTP allows.
  - It followed the `http://` to `https://` redirect automatically, then treated "the request succeeded" as "plain HTTP serves the app".
- **What I did instead:** the checker now reads headers case-insensitively, and inspects the redirect instead of following it. A checker that cries wolf is as dangerous as one that stays silent, because real failures get ignored.
  - Commit: [0c0d3f1](https://github.com/PailaJeevan/trustvault/commit/0c0d3f1)

---

## Template for new entries

### N. YYYY-MM-DD: short title (tag: authorisation / audit / upload / other)

- **Asked:** (prompt or a fair summary)
- **Produced:** (what the tool gave you)
- **What was wrong, specifically:**
- **What I did instead:** (with test name and commit link)
