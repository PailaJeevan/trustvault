# TrustVault threat model

How I believe this system could be broken, what I did about each one, and what I knowingly left open.

**Status key.** *Closed*: a control exists and a named test proves it. *Reduced*: the risk is smaller but not gone. *Accepted*: I know it is open and say why.

**How to check my claims.** Every *Closed* entry names the test that proves it. Two scripts do what you said you would do, take a check out and run the tests:

- `python -m scripts.mutation_check` removes **67 named checks** one at a time (authorisation, revocation, audit, MFA, upload and demo safety) and shows the suite fails for each. The mutant name is given beside each entry.
- `python -m scripts.mutation_sweep` finds **every** `authorize(...)` call and **every** `@login_required` / `@roles_required` decorator in `app/routes/` automatically, deletes each in turn and runs the suite. It covers checks nobody remembered to list.

Both must report every mutant as killed by a failing assertion, not a crash.

## The attacker I designed against

1. **A signed-in user reaching for documents they were not given.** This is the judge's position: a colleague, an ex-employee, an external partner.
2. **Someone with no account**, on the public internet.
3. **A malicious or careless administrator.**
4. **Someone who gets a copy of the database file**, through a backup, a misconfigured host or a stolen laptop.
5. **Someone who controls the server and its environment.** I cannot defend against this one, and I say so in OP-6.

## Where the authorisation decision is made

Every route that takes a document id calls `authorize(document_id, action)` in `app/authz.py` before it reads or changes anything. That function:

- reads the document;
- refuses trashed or purged documents;
- computes the caller's level from the database at that moment (`owner`, or a grant that is unrevoked and unexpired);
- checks that level against `ACTION_LEVELS`.

- for actions that **widen** access (`share`, `restore`), also requires the `owner` role.

Role never *grants* access to a document; it can only take the ability to widen access away. So an admin has no route to content, and an owner who is demoted to viewer can still revoke and delete but can no longer hand their documents to anyone.

Writes, and the download itself, call `authorize()` inside a `BEGIN IMMEDIATE` transaction. That holds SQLite's write lock from the check until the audit record commits, so a revoke cannot land between "allowed" and "sent". If you delete the `authorize` line in `download()`, 18 tests fail (mutant `download-authorize`). If you move it *before* the lock, the race test fails (mutant `download-toctou`).

---

## PT: I attacked the finished system. What I found

After building it, I attacked it the way you will. Method:

1. **A fuzzer over all 51 API routes**, taken from Flask's own route map so none could be missed. It used malformed ids, wrong types, injection strings and huge numbers, signed in as a stranger, another owner, the owner and the admin. It looked for any 5xx and any 2xx to a stranger on a secret document. Result: no leaks.
2. **Hand-written attacks** on design-level weaknesses. These found the holes below.
3. **The mutation sweep above.**

| ID | What I tried | What happened | Fix | Status | Proof |
|---|---|---|---|---|---|
| PT-1 | **Redaction bypass.** The owner uploads a redacted v2 over an unredacted v1. A *reader* asks for `?version=1`. | The reader got the unredacted original. The version list also showed the old file name. | New action `download_history` (owner and edit only). Readers get the current version, and only see the current version in the list. Refusals are audited. | Closed | `RedactionBypass`; mutants `history-download`, `history-list` |
| PT-2 | **Hash confirmation through the audit trail.** The admin cannot open files, but the audit stored each file's SHA-256. For a templated document ("your salary is INR N,00,000") the admin hashes every plausible N. | **The admin recovered the salary (18) in 18 guesses, without opening the file.** I did not see this one coming. | The audit now records a keyed fingerprint, `HMAC(audit_key, sha256)`. It still identifies the exact file for anyone holding the server key, but cannot be brute-forced from the audit or the export. Readers still see the raw hash, because they can download the file anyway. | Closed | `HashConfirmation`; mutant `content-fp` |
| PT-3 | **`HEAD` request** on the download URL. | Flask runs the GET handler for HEAD and drops the body, so a "downloaded" audit record was written although no byte left the server: false evidence. | Every `HEAD` request to `/api/` is refused with 405 before any handler runs. | Closed | `HeadIsNotADownload`; mutant `head` |
| PT-4 | **Trash oracle.** A former grantee calls `restore` on a trashed document. | 403 "no permission", while a stranger gets 404. That tells the ex-grantee "it's in the trash" as opposed to "gone". | A trashed document is 404 for everyone but its owner, on every action. | Closed | `TrashOracle`; mutant `trash-oracle` |
| PT-5 | **Deeply nested JSON** (`[[[[…` × 100,000). | 500: Python's recursion limit. | Treated as invalid JSON (400). | Closed | `test_deeply_nested_json_is_a_400`; mutant `deep-json` |
| PT-6 | **`?page=99999999999999999999`** | 500: the number overflows SQLite's integer range. The fuzzer missed this; a test I wrote expecting it to pass caught it. | The page number is capped. | Closed | `test_huge_page_number_is_not_a_crash`; mutant `page-cap` |
| PT-7 | **Demo sabotage.** Maya's MFA key is public, so a judge can turn her MFA off for everyone. | Allowed. | Disabling MFA is refused on demo accounts in demo mode. | Closed (demo) | `test_demo_mfa_cannot_be_turned_off`; mutant `demo-mfa` |
| PT-8 | **Public demo passwords in production.** Someone runs `seed` on a real deployment. | Allowed. | `seed` refuses when `TV_ENV=production` unless `TV_DEMO_MODE=1`. | Closed | `test_seed_refuses_production_without_demo_mode`; mutant `seed-prod` |
| PT-13 | **Your test, applied to every check.** I deleted every `authorize()` call and every auth decorator, one at a time, and ran the suite. | **Only 28 of 69 removals were caught.** Deleting `@roles_required("admin")` from *reset password, reset MFA, create user, unlock, transfer and purge* left every test green: nothing called those routes as a non-admin. Removing `@login_required` from document routes changed nothing observable, because `authorize()` also refuses anonymous users, so no behavioural test could notice. Two narrowing routes (downgrade a grant, dismiss a suggestion) had no stranger test. | Three changes. (1) Every route **declares** its access rule (`@login_required`, `@roles_required`, `@public`), and `test_route_policy` fails the build for any `/api/` route without one, or an admin route without `roles:admin`. (2) Every admin action is called by an owner and two viewers with a body that *would* succeed for an admin, and must return 403 *and* leave a snapshot of users, documents and grants byte-identical. (3) Stranger tests for the narrowing routes. | Closed | `tests/test_route_policy.py`; `scripts/mutation_sweep.py` |
| PT-9 | `Origin: null` sign-in (sandboxed iframe, `file://`) | Refused, 403. | none needed | Holds | `test_login_from_origin_null_is_refused` |
| PT-10 | `text/plain` "simple request" CSRF, which browsers send cross-site without a preflight | Refused, 403. Nothing changed. | none needed | Holds | `test_text_plain_simple_request_cannot_change_state` |
| PT-11 | `X-HTTP-Method-Override: DELETE`, spoofed `X-Forwarded-For` | Ignored. The audit IP is not spoofable unless a trusted proxy is configured. | none needed | Holds | `test_method_override_headers_are_ignored`, `test_spoofed_forwarded_for_is_not_trusted_without_a_proxy` |
| PT-12 | An editor plants HTML as a `.txt` version for readers to open | Served as `application/octet-stream`, as an attachment, sandboxed. Never rendered. | none needed | Holds | `test_editor_planted_html_is_never_rendered` |

---

## AC: Access control

| ID | Threat | What I did | Status | Proof |
|---|---|---|---|---|
| AC-1 | **IDOR**: change the document id in any URL (metadata, download, versions, grants, activity, suggestions, restore, delete). | One `authorize()` on every route. A walker test hits **all 13 document routes** as three different strangers (a viewer, another owner, the admin) and checks that each gets 404, sees no title or content, and changes nothing. | Closed | `test_access_control.EveryRouteRefusesStrangers`; mutants `owner`, `grant-user`, `no-level` |
| AC-1b | **Enumeration**: telling "exists but not yours" apart from "doesn't exist". | Both return the same 404 body. Ids are 128-bit random, not sequential. | Closed | `test_unknown_and_forbidden_documents_look_identical` |
| AC-2 | **Escalation within a document**: a reader edits, an editor deletes or reshares, or a grantee alters their own grant. | `ACTION_LEVELS`: read < edit < owner. Only the owner can delete, restore, share or see activity. An editor cannot pass access on. | Closed | `GrantLevelsAreEnforced`; mutants `action-level`, `edit-authorize`, `delete-authorize`, `share-authorize` |
| AC-3 | **Admin backdoor**: the admin role reads everything. | `authorize()` ignores role, and no admin route returns content. Admin sees metadata only (title, owner, grant count). Admin cannot transfer a document to themselves. | Closed (see AC-3b) | `AdminHasNoBackdoor`; mutant `transfer-self` |
| AC-3b | **Admin works around AC-3** by resetting a user's password and signing in as them, or by creating a puppet owner and transferring documents to it. | **Two-person rule:** resetting a password or two-step sign-in, transferring ownership, and making someone an administrator are only *requested* by one administrator; a different administrator must approve before anything happens. The requester cannot approve their own request or one about their own account, requests expire, checks re-run at approval time, and neither admin may receive a transfer. Every request, approval and rejection is audited and listed in Alerts. Two colluding administrators can still do it. | **Reduced**: needs two admins, fully audited | `test_one_admin_alone_cannot_reset_a_password`, `test_requester_cannot_approve_their_own_request`, `test_second_admin_approval_carries_it_out_and_records_both`, `test_transfer_needs_approval_and_neither_admin_may_receive` |
| AC-4 | **Id confusion**: using my document's URL with *your* grant id, suggestion id or version number. | Every child lookup is keyed by `(child_id, document_id)` from the authorised document, never by child id alone. Version numbers are integers checked against the document. | Closed | `IdConfusion`, `test_suggestion_id_from_another_document_is_refused`; mutant `grant-doc` |
| AC-5 | **Trashed or purged documents** stay reachable by grantees, or by "restore" from a non-owner. | Trashed means unreachable for every action except owner restore. Purged means the encrypted content is deleted and nothing is reachable. | Closed | `DeletedDocuments`; mutants `deleted`, `purged` |
| AC-6 | **No session at all**, or a forged cookie. | Every API route needs a session found in the database by token hash. | Closed | `Unauthenticated` |
| AC-7 | **Mass assignment**: sending `owner_id`, `role` or `deleted_at` in a JSON body. | `json_body()` rejects any field not on the allow-list for that route, rather than ignoring it. | Closed | `test_cannot_change_owner_through_metadata_update`; mutant `mass-assignment` |
| AC-8 | **Folder or group inheritance leaks**: given a folder to see one file, you see forty. | Designed out. There are no folders, groups or inheritance. Every grant names one person and one document. Categories are labels, not containers. | Closed by design | See WRITEUP.md |
| AC-9 | **Role-gated routes**: a viewer uploads, or a non-admin calls admin routes. | `roles_required()` decorator, with the refusal audited. | Closed | `test_non_admins_cannot_use_admin_routes`, `test_viewer_role_cannot_create_documents`; mutant `role` |
| AC-10 | **Grant to self, to the owner, or to a deactivated user.** | Rejected in `_grantee()`. | Closed | `test_cannot_grant_to_self_or_owner` |
| AC-11 | **Race between check and use**: a revoke lands between the access check and the file being sent. | Download and every write call `authorize()` inside `BEGIN IMMEDIATE`. A revoke needs the same lock, so it lands strictly before (refused) or after (download already recorded). | Closed | `test_governance.CheckThenActRace`: a second connection holds the lock mid-revoke while a download waits; the download must come back 404. Mutant `download-toctou` moves the check before the lock and the test fails. (In v1 this was argued, not tested.) |
| AC-16 | **A route added without any access rule** (a future endpoint, or a decorator lost in a merge). | Every `/api/` route must declare `signed-in`, `roles:...` or `public`. The test enumerates Flask's route map, so new routes are covered automatically. Anonymous calls to every non-public route must return 401. | Closed | `EveryRouteDeclaresItsAccessRule`; sweep |
| AC-17 | **An admin action reachable by a non-admin**: password reset, MFA reset, user creation, transfer, purge. Any one of these is a full takeover. | `@roles_required("admin")` on the whole admin blueprint. Tested by calling *each* admin route as owner and viewer and checking nothing changed. A second test fails if an admin route is added without being added to that list. | Closed | `AdminRoutesRefuseEveryoneElse`; sweep |
| AC-13 | **An owner shares with an administrator.** | That administrator then has exactly the access granted, like anyone else. It is the owner's decision and it is audited. The admin *role* still adds nothing. | By design | `authorize()` ignores role |
| AC-14 | **An admin renames an account to impersonate someone**, for example renames Mallory to "Olivia Owner" so an owner shares with the wrong person. | Emails are unique and not editable, and the share picker always shows the email under the name. The rename is audited (`admin.user_update`). | **Accepted**, detectable | |
| AC-15 | **A legitimate reader exfiltrates**: prints, screenshots, forwards the downloaded file. | No system can stop a person who is allowed to read. No watermarking. The download record (who, when, which version, fingerprint) and the volume alert are the evidence. | **Accepted** | `test_download_record_names_the_exact_file` |
| AC-12 | **A demoted owner keeps widening access**: their role changes from owner to viewer, but they still own documents and keep sharing them. Found by probing v1, where it returned 201. | Widening actions (`share`, `restore`, upgrading a grant from read to edit, extending or removing an expiry) also need the owner role. Narrowing (revoke, downgrade, shorten, delete) stays allowed, so they can still clean up. Alert: "documents owned by people who are no longer owners". | Closed | `WideningNeedsOwnerRole`, `test_demoted_owner_can_shorten_but_not_extend_or_remove_expiry`; mutants `widen-role`, `widen-detect` |

## RV: Taking access away

My definition of "immediately": the next HTTP request made after the revoke commits is refused, on every route, including requests on a session and URL issued before the revoke. This works because **nothing that confers access is ever handed to the client.** There are no signed URLs, no JWTs carrying permissions, and no cached permission decisions. The only thing a client holds is an opaque session id, and every request re-reads `sessions`, `users` and `grants`.

**The cost:** one indexed SQLite lookup per request and per document. I cannot scale out to a CDN or put files behind pre-signed object-storage URLs without changing this definition. I chose that trade on purpose.

| ID | Threat | What I did | Status | Proof |
|---|---|---|---|---|
| RV-1 | Revoked grantee keeps using an open page, a download link or a search result. | Grants are re-read on each request; the revoked row is excluded. | Closed | `test_revocation_stops_the_very_next_request_on_the_same_session`; mutant `revoked` |
| RV-2 | Time-limited grant keeps working after it expires. | Expiry is compared in the same query as the access check, and in search. | Closed | `ExpiredGrant`; mutant `expiry` |
| RV-3 | Leaver: deactivated user's existing session keeps working. | Deactivation deletes their sessions. Separately, the session lookup refuses inactive users, so either control alone is enough. | Closed | `test_deactivated_user_is_cut_off_mid_session`, `test_deactivation_is_enforced_even_if_session_rows_survived`; mutant `session-active` |
| RV-4 | Role change does not take effect until the next login. | Changing role ends all of that user's sessions. | Closed | `test_role_change_ends_sessions`; mutant `revoke-sessions-on-role` |
| RV-5 | Password reset or change leaves a stolen session alive. | Admin reset ends all sessions. Self-change ends all *other* sessions. | Closed | `test_admin_password_reset_ends_sessions`, `test_own_password_change_ends_other_sessions` |
| RV-6 | Copying the cookie and replaying it after logout. | Logout deletes the session row server-side. | Closed | `test_logout_kills_the_session_server_side` |
| RV-7 | Abandoned session on a shared computer. | 30-minute idle timeout and 8-hour absolute lifetime. | Closed | `test_idle_session_expires`, `test_absolute_session_lifetime`; mutant `session-idle` |
| RV-8 | **A file already downloaded before revocation.** | Nothing a server can do. The audit trail records exactly who downloaded which version (SHA-256) and when, which is the evidence the brief asks for. | **Accepted** | `test_download_record_names_the_exact_file` |
| RV-9 | **Large download in progress** at the moment of revocation. | Files are at most 10 MB and are sent from memory once authorised. A response already authorised finishes. | **Accepted** | (by design) |
| RV-10 | Ownership transfer leaves the old owner with access. | The old owner gets no grant. The new owner's previous grant is closed. | Closed | `test_transfer_moves_access_and_is_audited` |
| RV-11 | **Reactivated leaver gets everything back.** Deactivation stops sign-in but leaves grants in place, so reactivating the account by mistake, or for a returning employee, silently restores all access. | **Offboard** in one action: deactivate, end sessions, revoke every grant they hold (each audited), and list the documents they own for transfer. An alert counts live grants still held by deactivated accounts. | Closed | `test_offboard_revokes_everything_so_reactivation_restores_nothing`; mutant `offboard-grants` |
| RV-12 | **Access that is never reviewed only grows.** | Owner **Access review** page: every grant on every document you own, with last-download date and flags (never expires, outside your organisation, unused for 30 days, edit on HR or Legal, deactivated account, expiring soon). Bulk revoke. | Closed | `AccessReview` tests |
| RV-13 | **Bulk revoke used to revoke grants on someone else's document.** | Each grant id is resolved to its document, which goes through the same `authorize(doc, "manage")`, all in one transaction: if any grant is refused, none is revoked, and the refusal is audited. | Closed | `test_bulk_revoke_refuses_someone_elses_grant_and_changes_nothing`; mutant `review-authorize` |

## AU: The audit trail is evidence

| ID | Threat | What I did | Status | Proof |
|---|---|---|---|---|
| AU-1 | **Edit a record** to change who downloaded something. | Layer 1: SQLite triggers abort any `UPDATE` or `DELETE` on `audit_log`. Layer 2: each row stores `HMAC-SHA256(audit_key, prev_hash ‖ row)`, so any edit breaks verification from that row onward. The key lives in the environment, not the database, so someone holding only the DB file cannot recompute the chain. Admin Alerts re-verify the whole chain on every view. | Closed | `test_database_refuses_update_and_delete`, `test_edited_row_is_detected_even_if_triggers_are_dropped` |
| AU-2 | **Delete a record** from the middle. | Breaks the chain (sequence gap and prev_hash mismatch). | Closed | `test_deleted_row_is_detected` |
| AU-2b | **Truncate the tail**: delete the most recent records. A hash chain cannot detect this on its own, because the remaining chain is still consistent. I found this when my first test wrongly assumed it would. | Two outside witnesses: (a) every record's seq and hash is written to stdout, and the hosting platform keeps those logs separately; (b) admin export (JSONL with hashes) plus `scripts/verify_audit.py --against export.jsonl` proves a later database is missing records. | **Reduced**: detection depends on someone keeping exports or logs | `test_deleting_the_tail_is_detected_by_comparing_with_an_export` |
| AU-3 | **Refused attempts not recorded.** In particular, a denial raised inside a write transaction would be rolled back along with the transaction. | Denials inside a transaction are queued and written by the error handler after the rollback. Recorded denials include document reads and downloads, every refused action, failed logins (with reason), lockouts, role failures, CSRF and bad-origin refusals. | Closed | `test_refused_attempts_are_recorded`, `test_refusals_inside_transactions_are_still_recorded`; mutant `deny-audit` |
| AU-4 | **Insert a forged record.** | Cannot produce a valid HMAC without the key. | Closed | `test_forged_row_without_key_is_detected` |
| AU-5 | **An action happens without a record**, for example the disk is full. | The audit row is written in the same transaction as the action. A download's record commits before any byte is sent; if the write fails, the download fails (fail closed). | Closed | `test_audit_failure_blocks_the_download`, `test_every_required_event_is_recorded_with_actor` |
| AU-6 | **Spoofed IP** in the record via `X-Forwarded-For`. | `ProxyFix` trusts exactly `TV_TRUSTED_PROXIES` hops (1 on the host). Locally it trusts none. | Closed (config) | `app/__init__.py` |
| AU-7 | **Someone holding both the DB and the audit key** rewrites the whole chain consistently. | Out of reach of the chain itself. Only the outside witnesses (AU-2b) catch it. | **Accepted** | See OP-6 |
| AU-9 | **"Downloaded" means served, not received.** The record commits before the bytes are sent; if the connection drops, the audit still says downloaded. | Deliberate: recording first is what makes the trail complete (AU-5). Every download response also carries `X-TrustVault-Receipt`, the audit number of that exact download. | **Accepted** (errs towards over-recording) | `test_receipt_header_is_the_audit_record_of_this_download` |
| AU-10 | **The audit stores the email typed at a failed sign-in.** If someone types their password into the email box, it is stored. | Needed to detect password spraying. Visible to admins only. Passwords are never logged anywhere else. | **Accepted** | |
| AU-11 | **Side channel through file size**: the audit records each file's size, visible to admins. | Size can hint at content (a longer salary figure). Much weaker than PT-2. | **Accepted** (Reduced) | |
| AU-12 | **No key rotation** for `TV_MASTER_KEY` or `TV_AUDIT_KEY`. | Rotating the audit key needs a signed checkpoint, and rotating the master key needs re-wrapping each blob's data key (cheap, because of the envelope design). Not built. | **Accepted** | |
| AU-8 | **Audit table filling the disk** through deliberate floods of denied requests. | Login is rate-limited per IP. Other denials need a valid session. No retention on audit by design (it is evidence). | **Accepted** at this scale | |

## AN: Authentication

| ID | Threat | What I did | Status | Proof |
|---|---|---|---|---|
| AN-1 | **Password guessing.** | Per-account lockout after 5 failures for 15 minutes (DB-backed, holds across workers). Per-IP limit of 20 attempts per 5 minutes (in memory, per worker). scrypt hashing. Minimum 12 characters. | Closed | `test_lockout_after_repeated_failures`, `test_ip_rate_limit`; mutant `lockout` |
| AN-1b | **Lockout as denial of service**: lock someone out by failing on purpose. | Inherent to lockout. Admin can unlock. Alerts show repeated failures per account and per IP. | **Accepted** | |
| AN-2 | **User enumeration** through login messages or timing. | Identical message and status for unknown email, wrong password, locked and deactivated. A dummy scrypt verify runs for unknown emails. | Closed | `test_unknown_email_and_wrong_password_look_the_same` |
| AN-3 | **Session theft from a DB copy.** | Only SHA-256 of the token is stored. | Closed | `test_database_holds_only_token_hashes` |
| AN-4 | **Session fixation.** | Login always mints a new token. | Closed | `test_login_issues_a_fresh_token` |
| AN-5 | **Cookie theft** via JavaScript or HTTP. | `HttpOnly`, `Secure`, `SameSite=Strict`, and the `__Host-` prefix in production. HSTS. | Closed | `test_cookie_flags` |
| AN-6 | **Shared demo accounts**: one judge changes a password and locks the others out. | `TV_DEMO_MODE=1` blocks self-service password change for seeded accounts. | Closed (demo only) | `auth_routes.change_password` |
| AN-7 | **Stolen or guessed password is enough to sign in.** | Optional two-step sign-in (TOTP, RFC 6238, standard library only). With it on, the password step returns only a short-lived, single-purpose challenge: no cookie, no session. Enabling it ends your other sessions. | Closed (opt-in) | `test_password_alone_gives_no_session_once_mfa_is_on`, `Totp.test_rfc6238_reference_vector`; mutant `mfa-required` |
| AN-8 | **MFA brute force**: 1,000,000 codes. | 5 attempts per challenge, a 5-minute challenge lifetime, and every wrong code counts towards the account lockout. | Closed | `test_challenge_cannot_be_brute_forced`, `test_wrong_code_is_refused_and_counts_towards_lockout`, `test_challenge_expires`; mutants `mfa-code`, `mfa-attempts`, `mfa-challenge-expiry` |
| AN-9 | **MFA code replay**: a code seen over a shoulder or in a proxy log is reused within its 30 seconds. | Two layers: the last accepted time step is stored and older or equal steps are refused, and the step is claimed with a conditional `UPDATE ... WHERE mfa_last_step < ?` so two simultaneous requests cannot both win. | Closed | `test_code_cannot_be_replayed`; mutant `mfa-replay` (removing one layer alone is caught by the other) |
| AN-10 | **A stolen session switches MFA off.** | Turning MFA off needs both the password and a current code. | Closed | `test_disabling_needs_password_and_code`; mutant `mfa-disable-code` |
| AN-11 | **MFA secret stolen from a DB copy.** | Encrypted with AES-GCM under the master key, bound to the user id. | Closed | `test_secret_is_encrypted_at_rest` |
| AN-14 | **Sign-in throttling shared by many people.** Judges behind one office NAT share an IP. Or, if the proxy setting is wrong, *every* user appears as the proxy's IP and 20 sign-ins lock everyone out. | The per-IP limit is generous (40 per 5 minutes, `TV_LOGIN_RATE_PER_IP`). The per-account lockout is the real control. `check_live` warns if the recorded IP is a private or proxy address. | Reduced | `test_ip_rate_limit` |
| AN-15 | **The only administrator gets locked out or deactivated.** | Lockout ends after 15 minutes. An admin cannot deactivate themselves. A second admin, or a database command run on the server, recovers it. No web recovery path, deliberately. | **Accepted** | `test_admin_cannot_demote_or_deactivate_self` |
| AN-12 | **MFA is not mandatory**, not even for administrators. | Kept optional so the demo works for the judges. Alerts list administrators without it. Making it required per role is a one-line policy plus an enrolment-on-login screen. | **Accepted** | |
| AN-13 | **No QR code** for setup; the key is typed in. | Avoids a third-party QR library (no new dependency, strict CSP). | **Accepted** (usability, not security) | |

## SS: Your own sessions

| ID | Threat | What I did | Status | Proof |
|---|---|---|---|---|
| SS-1 | **A lost laptop stays signed in.** | Account page lists every session (device, IP, last active) with "Sign out" per device and "Sign out everywhere else". Each session has a separate random public id, never the token or its hash. | Closed | `test_list_and_end_own_sessions`, `test_end_all_other_sessions` |
| SS-2 | **Ending someone else's session** by guessing or enumerating its id. | The delete is `WHERE public_id = ? AND user_id = <you>`, and an unknown or foreign id gives the same 404. | Closed | `test_cannot_end_someone_elses_session`; mutant `session-owner` |

## IN: Dashboards, activity feed, analytics

| ID | Threat | What I did | Status | Proof |
|---|---|---|---|---|
| IN-1 | **Dashboard counts or "recently changed" reveal documents you cannot open**, a classic side channel. | Every count and list is built on `VISIBLE_DOCUMENTS_SQL`, the same rule as search and `authorize()`. | Closed | `Dashboard` tests; mutant `dashboard-visibility` |
| IN-2 | **The activity feed shows events on other people's documents**, for example a grantee seeing who else was refused on a document shared with them. | The feed only covers documents you currently **own** (the same audience as the custody record), excluding your own actions. | Closed | `test_grantee_does_not_see_activity_on_documents_shared_with_them`; mutant `feed-owner` |
| IN-3 | **Admin analytics readable by anyone signed in.** | Admin role required. Counts and audit metadata only, never content. | Closed | `AdminStats.test_admin_only`; mutant `stats-role` |
| IN-4 | **The user cannot prove their own download was recorded.** | Every download response carries `X-TrustVault-Receipt`: the audit record number of that exact download, which the UI shows. | Closed | `test_receipt_header_is_the_audit_record_of_this_download` |
| IN-5 | **The custody seal is mistaken for a security control.** | It is a recognition aid: a picture generated from the file's SHA-256. The full hash is shown beside it and in the version list, and the hash is what proves integrity. | By design | `app/static/js/seal.js` |
| IN-6 | **Demo passwords in the front-end bundle.** | Shown only when the server reports demo mode. They are the same public credentials as in README, and they only exist in seeded demo data. A real deployment has `TV_DEMO_MODE` off, and nothing is listed. | **Accepted** (demo convenience) | `views/auth.js`, `GET /api/auth/config` |

## RT: Retention and legal hold

| ID | Threat | What I did | Status | Proof |
|---|---|---|---|---|
| RT-1 | **Evidence destroyed during a dispute**: the owner deletes a document an auditor or court needs. | Admin can place a **legal hold** (a reason is required). While held, delete is refused with 423 for everyone including the owner, and the refusal is audited. Releasing the hold is flagged in Alerts. | Closed | `test_hold_blocks_deletion_by_the_owner`; mutant `legal-hold-delete` |
| RT-2 | **Retention job purges a held document** that was already in the trash. | Purge skips held documents. The owner can still restore. | Closed | `test_hold_stops_purge_of_a_trashed_document`; mutant `legal-hold-purge` |
| RT-3 | **Legal hold used as a backdoor** to read the document. | A hold changes nothing about who can read it; the admin still gets 404. | Closed | `test_hold_gives_admin_no_access_and_needs_reason` |

## RQ: Forged requests and the browser

| ID | Threat | What I did | Status | Proof |
|---|---|---|---|---|
| RQ-1 | **CSRF**: another site makes the victim's browser grant access or delete. | Per-session CSRF token required in a header on every state change, compared in constant time. The cookie is `SameSite=Strict`. Login must be JSON. | Closed | `ForgedRequests`; mutant `csrf` |
| RQ-2 | **Cross-origin requests.** | Any state-changing request with a foreign `Origin` is refused and audited. No CORS headers are ever sent. | Closed | `test_cross_origin_request_is_refused_even_with_token`; mutant `origin` |
| RQ-3 | **Stored XSS** through a document title, description, filename or user name. | The UI only ever uses `textContent`; there is no `innerHTML` in `app.js`. CSP `script-src 'self'` with no inline script, so injected markup could not run even if inserted. | Closed | `test_title_is_stored_as_text_not_markup`, `test_security_headers` |
| RQ-4 | **Clickjacking** the share button. | `frame-ancestors 'none'` and `X-Frame-Options: DENY`. | Closed | `test_security_headers` |
| RQ-6 | **Sibling sites on the same parent domain.** The demo runs at `*.onrender.com`, where other people host apps (the same applies on `*.pythonanywhere.com`). A sibling could plant ("toss") a session cookie, or send same-site requests that `SameSite` does not stop. | The cookie uses the `__Host-` prefix, which browsers refuse from another subdomain. The CSRF token and the exact-Origin check do not depend on site boundaries. I don't rely on whether the parent domain is on the Public Suffix List. | Closed | `test_cookie_flags`, `ForgedRequests` |
| RQ-7 | **Login CSRF** (session swapping): a hostile page signs the victim into the *attacker's* account, so the victim uploads into it. | Login must be JSON, which forces a CORS preflight that is never approved, and a foreign Origin is refused. | Closed | `test_login_requires_json`, `test_login_from_origin_null_is_refused` |
| RQ-8 | **Document ids leaking through the `Referer` header** to other sites. | `Referrer-Policy: no-referrer`. Ids are not secrets anyway (every access is checked). | Closed | `test_security_headers` |
| RQ-9 | **Cross-origin reads**: CORS misconfiguration, JSON hijacking, XSSI. | No CORS headers, ever. Every response is a JSON *object*, with `nosniff`. | Closed | `test_no_cors_headers_are_ever_sent` |
| RQ-10 | **Verb tampering**: `HEAD` (PT-3), `X-HTTP-Method-Override`. | HEAD is refused on the API. Override headers are ignored. | Closed | PT-3, PT-11 tests |
| RQ-11 | **The in-app viewer as an XSS or tracking hole**: an uploaded `.md`, `.csv` or `.txt` carrying markup, or a view that leaves no trace. | The viewer builds Markdown, CSV and text from `textContent` only, so markup is shown as characters. Images are raster PNG/JPEG shown from a `blob:` URL; the CSP allows `blob:` for `img-src` only, never for scripts. The viewer fetches through the same download route, so `authorize()` runs and the view is audited with `purpose: view` before any byte is sent. Unknown purposes are refused (400). | Closed | `test_viewer_and_expiry` (view audited, stranger 404, bad purpose 400, CSP blob scope) |
| RQ-12 | **Step-up prompt bypassed or phished.** | The prompt only collects a password (and code) and posts it to `/api/auth/reauth` on our own origin. The server decides whether recent re-authentication is needed; the UI cannot skip it, it can only retry once after the server accepts. | Closed | step-up tests in the suite; `check_live` "admin step-up" |
| RQ-5 | **Sensitive responses cached** by a proxy or shared computer. | `Cache-Control: no-store` on every API response and download. | Closed | `test_api_responses_are_not_cached` |

## UP / ST: Uploads and storage

| ID | Threat | What I did | Status | Proof |
|---|---|---|---|---|
| UP-1 | **Active content uploaded**: HTML, SVG, JS, executables. | Extension allow-list only (pdf, png, jpg, txt, csv, md, docx, xlsx, pptx). | Closed | `test_rejects_active_content_types`; mutant `upload-allowlist` |
| UP-2 | **Type spoofing**: an exe renamed `.pdf`. | Magic bytes are checked per type. Office files must be a valid ZIP with the right parts. Text must be UTF-8 with no NUL. The browser's Content-Type is ignored. | Closed | `test_rejects_content_that_does_not_match_extension`; mutant `upload-magic` |
| UP-3 | **Dangerous documents**: PDF JavaScript or launch actions, Office macros. | PDFs containing `/JavaScript /JS /Launch /EmbeddedFile /RichMedia /XFA` are refused. Office files containing `vbaProject.bin` are refused. | Reduced: pattern-based, an obfuscated PDF can evade it | `test_rejects_pdf_with_javascript_and_office_with_macros` |
| UP-4 | **Path traversal** through the filename. | The filename is display-only. Storage is keyed by random id in the DB; there is no filesystem path. The name is still reduced to a basename and stripped of control and bidi characters. | Closed | `test_path_traversal_in_filename_is_neutralised`, `test_bidi_override_in_filename_is_removed` |
| UP-5 | **Huge uploads, zip bombs, form floods.** | 10 MB limit at the WSGI layer and again in code. ZIPs are inspected via the central directory only and never decompressed. Form parts limited. | Closed | `test_empty_and_oversized_files` |
| UP-6 | **Malware inside an allowed type**, for example an exploit PDF. | No antivirus scanning. Files are only ever delivered as downloads, never rendered on our origin. | **Accepted**: would add ClamAV in production | |
| ST-1 | **Stolen DB file or backup** reveals file contents. | AES-256-GCM per file with a random data key, wrapped by a master key held in the environment. The blob id is bound as associated data, so ciphertext moved between rows will not decrypt. | Closed | `test_file_content_is_encrypted_at_rest` |
| ST-2 | **Guessable or public file URLs**, as with an S3 bucket or static folder. | Files are not on the filesystem or any public URL; they are rows in the DB. The only route to bytes is `download()`. | Closed | `test_no_static_route_serves_stored_files` |
| ST-3 | **Download rendered in the browser** (HTML or SVG polyglot executes on our origin). | Always `application/octet-stream`, `Content-Disposition: attachment`, `nosniff`, and `CSP: sandbox` on the response. | Closed | `test_downloads_are_never_rendered_by_the_browser`; mutant `download-octet` |
| ST-4 | **Header injection** through the filename in `Content-Disposition`. | ASCII fallback with quotes, semicolons and control characters replaced, plus RFC 5987 encoding. | Closed | `test_header_injection_through_filename_is_impossible` |
| ST-5 | **Deleted content lingers** in free pages after purge. | `PRAGMA secure_delete=ON`. Content is encrypted anyway. | Reduced: backups taken earlier still contain it | |

## SR: Search and listings

| ID | Threat | What I did | Status | Proof |
|---|---|---|---|---|
| SR-1 | **Search leaks titles or counts** of documents you cannot open. | The access rule is in the SQL `WHERE` (`VISIBLE_DOCUMENTS_SQL`, the same rule as `access_level()`), so totals and pages only count visible documents. | Closed | `test_search_only_returns_accessible_documents`, `test_owner_filter_cannot_be_used_to_count_hidden_documents`; mutant `search-filter` |
| SR-2 | **Wildcard injection**: `%` or `_` matching everything. | LIKE input is escaped. | Closed | `test_wildcards_are_literal` |
| SR-3 | **SQL injection** in any filter or sort. | Parameterised queries everywhere. Sort is chosen from a fixed map. Category comes from a fixed list. | Closed | `test_sql_injection_attempts_are_plain_text`, `test_bad_filter_values_are_rejected` |
| SR-4 | **User directory used for enumeration.** | Viewers cannot list people. Owners see name and email of active users only, with no roles. | Reduced: an internal directory is a feature | `Directory` tests; mutant `directory-role` |
| SR-5 | **Admin sees document titles** of everything. | A choice, not a leak. Oversight of sharing is impossible without it. Titles also appear in audit. Content is never available to admin. | **Accepted** | |
| SR-6 | **Tags leak what hidden documents are about**, for example a tag `merger-zeta` showing up in someone's tag list. | Tag filters are ANDed onto the visibility rule. The list of tags offered is computed only from documents you can open. Tags are validated labels (letters, numbers, `-`, `_`), at most 10 per document, and editing them needs edit access. | Closed | `test_tags_never_widen_or_leak`, `test_tag_validation_and_edit_rights`; mutant `tag-visibility` |

## AI: Access suggestions

| ID | Threat | What I did | Status | Proof |
|---|---|---|---|---|
| AI-1 | **The machine widens access on its own.** | Suggestions write to `access_suggestions` and the audit log only; nothing in that code path touches `grants`. A grant needs a POST from the owner. The grant's audit record carries `source: suggestion`, the suggestion id and the human actor. | Closed | `test_suggestion_does_not_grant_anything`, `test_accepting_records_both_suggestion_and_decision` |
| AI-2 | **Accept another document's suggestion**, or a dismissed one. | Lookups by `(suggestion_id, document_id, status='pending')`. | Closed | `test_suggestion_id_from_another_document_is_refused`, `test_dismissed_suggestion_cannot_be_accepted` |
| AI-3 | **Suggestions leak who has access to other documents.** | Only the owner sees suggestions, and they are computed only from that same owner's own documents. Nothing is revealed that the owner could not already see. | Closed | `test_only_the_owner_can_see_or_accept_suggestions` |
| AI-4 | **Document data sent to a third-party AI service.** | I deliberately used a rule, not an external LLM, so no confidential data leaves the system. | Closed by design | |

## OP: Operations and things outside the code

| ID | Threat | What I did | Status |
|---|---|---|---|
| OP-1 | **Default or missing keys** in production. | In production the app refuses to start without both keys, and refuses if they are equal. Dev keys exist only outside production. | Closed |
| OP-2 | **Losing the master key** means losing every file. | Documented in README: keep it in a password manager. | Accepted (operational) |
| OP-3 | **Verbose errors** leak internals. | Generic 500 body; the stack trace goes only to the server log. | Closed |
| OP-4 | **Demo credentials are public.** | They are seed accounts on demo data only. `TV_DEMO_MODE` protects them. `python -m scripts.seed --reset` restores the demo. | Accepted |
| OP-5 | **Single SQLite file** is a single point of failure. | WAL mode, and an online backup via `sqlite3 .backup` is documented. Fine at this scale; Postgres is the next step. | Accepted |
| OP-6 | **Server or host compromise**: an attacker with the process environment has both keys and the DB. | Out of scope for application code. Mitigations would be a KMS or HSM for keys, and audit shipping to append-only external storage (WORM). | Accepted |
| OP-7 | **Dependency vulnerabilities.** | Three direct dependencies, version ranges pinned. Should run `pip-audit` in CI. | Reduced |
| OP-8 | **Denial of service**: slow uploads, many requests. | Size limits only. No general rate limiting beyond login. | Accepted |
| OP-9 | **No external sharing links.** External people get a normal viewer account (see `ext@partner.test`). | Public links are the most common source of "the link still works after they left". Not building them is the control. | Closed by omission |
| OP-10 | **One judge sabotages the shared demo.** With the demo admin account, resetting Olivia's password locks every other judge out. Found by probing v1, where it returned 200. | With `TV_DEMO_MODE=1`, password reset, MFA reset, offboarding and MFA enrolment are refused on the seeded accounts. Reversible changes (deactivate, role) stay allowed so revocation can be tested. Judges can create their own accounts to try the rest. | Closed (demo only) | `DemoProtection`; mutant `demo-protect` |
| OP-12 | **Judges change the shared demo state** (revoke grants, delete documents, demote Olivia) and confuse each other. | Destructive account actions are blocked on demo accounts (OP-10, PT-7). The rest is reversible, and `python -m scripts.seed --reset` restores everything. | **Accepted** | |
| OP-13 | **Hostile files uploaded to the public demo** for other judges to download. | Allow-list plus content checks. Always delivered as a sandboxed attachment. No antivirus (UP-6). | **Accepted** | |
| OP-14 | **Expiry dates are end-of-day UTC.** "Until 21 Nov" ends at 05:29 on 22 Nov in India. | The UI says "until"; the exact UTC time is in the API. Per-user time zones are not built. | **Accepted** | |
| OP-15 | **Timing side channels** telling "exists but not yours" from "doesn't exist". | Both paths do one indexed lookup and one audit write, then return the same body. A remaining difference of a few hundred microseconds, against 128-bit random ids, gives nothing usable. | **Accepted** (negligible) | |
| OP-16 | **In-memory per-IP limiter**: counts per worker and grows with distinct IPs. | A restart clears it. A shared store (Redis) is the production answer. | **Accepted** | |
| OP-17 | **The hosting platform deletes the evidence.** On free hosts with an ephemeral disk (Render Free wipes it on restart and after 15 minutes idle), the database and the **audit trail** disappear, and "prove who reached it, afterwards" fails. | Documented in DEPLOY.md with a comparison table. PythonAnywhere free, or Render Starter with a persistent disk, keep the data. On ephemeral hosts the container re-seeds the demo on every start, so the site is never empty. The stdout witness line per audit record (AU-2b) still lands in the platform's log stream, which outlives the disk. | **Accepted on Render Free; Closed on a persistent host** | `docker-entrypoint.sh`, `render.yaml` |
| OP-11 | **Upgrading a deployed database** loses data or half-applies. | Versioned migrations (`app/migrations.py`, `PRAGMA user_version`). Each runs once, in its own exclusive transaction, applied automatically on start. | Closed | `Migrations.test_a_version_1_database_upgrades_in_place` |

## What I would do next, in order

1. Make MFA mandatory for administrators and owners (AN-12), with a QR code (AN-13).
2. Ship audit records to append-only external storage, which closes AU-2b and AU-7.
3. Require a third approver, or a waiting period, for approvals made by two admins in quick succession      (AC-3b collusion).
4. Antivirus scanning on upload (UP-6).
5. Email owners a monthly summary from their Access review page.
