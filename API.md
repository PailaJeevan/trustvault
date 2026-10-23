# TrustVault API

All endpoints are under `/api`, take and return JSON unless noted, and send `Cache-Control: no-store`.

**Authentication.** Sign in with `POST /api/auth/login`. This sets an HttpOnly session cookie and returns a `csrfToken`.

**State changes.** Every request that changes state (POST, PATCH, DELETE), except login, must send that token as `X-CSRF-Token`. Any request with a foreign `Origin` header is refused.

**Errors** have the shape `{"error": "<code>", "message": "<human text>"}`.

| Status | Meaning |
|---|---|
| 401 | Not signed in, or the session has ended. |
| 403 | Your role or access level does not allow this. |
| 404 | No such document, *or* you have no access to it. These two are deliberately indistinguishable. |
| 400 / 409 / 413 / 415 / 429 | Bad input / conflict / file too large / file type refused / too many attempts. |

**Two-step sign-in.** If MFA is on for the account, `login` returns `{"mfa_required": true, "challenge": "..."}` and sets **no** cookie. Send the challenge with a code to `/auth/login/mfa`.

**Document levels** are computed per request in `app/authz.py`:

- **owner**: `documents.owner_id` is you;
- **edit** or **read**: you hold a grant that is not revoked and not expired.

Role never grants document access. Actions that **widen** access (share, restore, upgrade or extend a grant) additionally require the `owner` role.

## Auth

| Method & path | Who may call | Notes |
|---|---|---|
| `POST /auth/login` `{email, password}` | Anyone | Same 401 for unknown, wrong, locked or deactivated. 5 failures lock the account for 15 min; 20 tries per IP per 5 min. |
| `POST /auth/logout` | Signed in | Deletes the session server-side. |
| `GET /auth/me` | Signed in | Current user and CSRF token. |
| `POST /auth/login/mfa` `{challenge, code}` | Anyone holding a challenge | 5 attempts per challenge, valid 5 minutes. Wrong codes count towards the account lockout. Codes cannot be reused. |
| `POST /auth/password` `{current_password, new_password}` | Signed in (not demo accounts in demo mode) | Ends your other sessions. |
| `POST /auth/mfa/setup` `{current_password}` | Signed in, MFA off (not demo accounts in demo mode) | Returns `secret` and `otpauth_uri`. MFA is not on until confirmed. |
| `POST /auth/mfa/enable` `{code}` | Signed in, after setup | Turns MFA on and ends your other sessions. |
| `POST /auth/mfa/disable` `{current_password, code}` | Signed in, MFA on | Needs both the password and a code. |
| `GET /auth/sessions` | Signed in | **Your own** sessions: `public_id`, device, IP, times, `current`. |
| `DELETE /auth/sessions/{public_id}` | Signed in | Ends one of **your** sessions. 404 for anyone else's. |
| `POST /auth/sessions/end-others` | Signed in | Ends all of your sessions except this one. |

## Documents

| Method & path | Who may call | Notes |
|---|---|---|
| `POST /documents` (multipart: `title`, `category`, `description`, `tags`, `file`) | Role **owner** | Creates a private document; you are its owner. File validated (see THREATS UP-*). |
| `GET /documents?q=&owner=&category=&from=&to=&scope=all\|mine\|shared&sort=newest\|oldest\|title\|updated&page=&page_size=` | Signed in | Only documents you can open, enforced in the query. `from`/`to` are `YYYY-MM-DD` on created date. `tag=` filters by tag. The response's `tags` lists only tags on documents you can open. |
| `GET /documents/trash` | Signed in | Your own trashed documents. |
| `GET /documents/{id}` | Level read, edit or owner | Metadata, versions (readers see only the current version), `my_access`. |
| `GET /documents/{id}/download[?version=n][&purpose=download\|view]` | Current version: read, edit or owner. **Earlier versions: edit or owner only** (they may be the unredacted original) | Always `application/octet-stream` as an attachment. Audited before any byte is sent; the audit stores a keyed fingerprint, not the raw hash. `HEAD` is refused (405). `purpose` (default `download`) is written into the audit record; `view` is what the in-app viewer sends; anything else is 400. Document JSON also carries `my_expires_at`: when *your* grant ends (null for owners and for grants without expiry). |
| `PATCH /documents/{id}` `{title?, description?, category?, tags?}` | Level edit or owner | Unknown fields are refused. `tags`: a list of up to 10 labels. |
| `POST /documents/{id}/versions` (multipart: `file`) | Level edit or owner | Adds version n+1; old versions are kept. |
| `DELETE /documents/{id}` | Owner | Soft delete: nobody can open it until restored. Purged after 30 days. **423** if under legal hold. |
| `POST /documents/{id}/restore` | Owner **with owner role** | Trashed, unpurged documents only. |
| `GET /documents/{id}/activity` | Owner | This document's audit records, including refusals. |

## Sharing

| Method & path | Who may call | Notes |
|---|---|---|
| `GET /documents/{id}/grants` | Owner | Live grants and the last 20 revoked. |
| `POST /documents/{id}/grants` `{user_id, permission: read\|edit, expires_at?}` | Owner **with owner role** | The target must be active, not the owner, and not already granted (409). Expiry must be in the future and at most 366 days away. |
| `PATCH /documents/{id}/grants/{grant_id}` `{permission?, expires_at?}` | Owner. Upgrading to edit, extending or removing the expiry also needs the **owner role** | The grant must belong to this document. |
| `DELETE /documents/{id}/grants/{grant_id}` | Owner | Revokes. Takes effect on the grantee's next request. |
| `POST /documents/{id}/suggestions` | Owner **with owner role** | Returns suggested people and reasons. **Changes no access.** Audited as `suggestion.shown`. |
| `POST /documents/{id}/suggestions/{sid}/accept` `{permission, expires_at?}` | Owner **with owner role** | Creates the grant (`source: suggestion`) and audits both the grant and the decision. |
| `POST /documents/{id}/suggestions/{sid}/dismiss` | Owner | Audited. |
| `GET /users/directory?q=` | Role owner or admin | Active users' id, name and email (at most 25). |

## Dashboard and activity

| Method & path | Who may call | Notes |
|---|---|---|
| `GET /auth/config` | Anyone | `{demo_mode}` only. Lets the sign-in page offer the demo accounts on the demo site. |
| `GET /dashboard` | Signed in | Counts and the 6 most recently changed documents **you can open**. Owners also get access-health numbers. |
| `GET /activity?limit=` | Signed in | Events by other people on documents **you own**, newest first, with `unread`. |
| `POST /activity/seen` | Signed in | Marks your feed as read. |

Every successful download also returns the header `X-TrustVault-Receipt: <audit record number>`.

## Access review

| Method & path | Who may call | Notes |
|---|---|---|
| `GET /review/grants` | Signed in | Live grants on documents **you own**, with `last_download` and `flags` (`no_expiry`, `external`, `unused`, `sensitive_edit`, `inactive`, `expiring`). |
| `POST /review/revoke` `{grant_ids: [...]}` | Signed in | Up to 100. Each grant goes through `authorize(document, "manage")`. All or nothing. |

## Administration (role admin only)

| Method & path | Notes |
|---|---|
| `GET /admin/users` | All accounts with status and lock state. |
| `POST /admin/users` `{email, name, role, password}` | Creates an account. |
| `PATCH /admin/users/{id}` `{role?, active?, name?}` | Cannot change your own role or status. Role or status change ends that user's sessions. |
| `POST /admin/users/{id}/reset-password` `{new_password}` | Ends their sessions and unlocks the account. |
| `POST /admin/users/{id}/unlock` | Clears the lockout. |
| `POST /admin/users/{id}/reset-mfa` | For a lost phone: turns MFA off and ends their sessions. Flagged in alerts. Refused for demo accounts in demo mode. |
| `POST /admin/users/{id}/offboard` | Deactivates, ends sessions, revokes every grant they hold, and returns `documents_to_transfer`. Not yourself. Refused for demo accounts in demo mode. |
| `GET /admin/documents` | **Metadata only** (title, owner, grant count, state). No content route exists for admins. |
| `POST /admin/documents/{id}/transfer` `{new_owner_id}` | The new owner must be an active owner-role user and **not the calling admin**. Flagged in alerts. |
| `POST /admin/documents/{id}/legal-hold` `{hold: true\|false, reason}` | Places (a reason is required) or releases a legal hold. While held, the document cannot be deleted or purged. Gives the admin **no** access. |
| `POST /admin/purge-expired` | Destroys the content of documents trashed longer than the retention period. |
| `GET /admin/audit?actor=&action=&outcome=&document_id=&actor_id=&target_user_id=&from=&to=&page=&page_size=` | `action` accepts a prefix such as `document.*`. |
| `GET /admin/audit/verify` | Recomputes the HMAC chain and reports where it first breaks, if anywhere. |
| `GET /admin/audit/export` | Full log as JSON lines including hashes. The export itself is audited. |
| `GET /admin/stats` | Allowed and refused events per day for 14 days, totals, the most-refused actors and the activity mix for 7 days. Metadata only. |
| `GET /admin/alerts` | Chain integrity, probing, failed sign-ins, download spikes, sharing bursts, privileged admin actions, forged requests, documents without an active owner. |

## Other

| Method & path | Who | Notes |
|---|---|---|
| `GET /` | Anyone | The single-page UI. |
| `GET /healthz` | Anyone | `{"status":"ok"}`. |
