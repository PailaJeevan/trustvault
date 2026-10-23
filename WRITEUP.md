# TrustVault write-up

## What I built

A document platform with three roles (administrator, owner, viewer) and these features:

- per-document read and edit grants to named people, with optional expiry;
- versions;
- soft delete with a 30-day trash, then purge;
- search by name, owner, category and date;
- validated uploads;
- files encrypted at rest;
- a hash-chained audit trail that records refusals as well as successes;
- an administrator view with alerts;
- rule-based access suggestions that never act on their own;
- optional two-step sign-in (TOTP) with replay protection;
- a page where people can see and end their own sessions;
- an owner **Access review** page with risk flags and bulk revoke;
- one-step **offboarding** of leavers;
- **legal hold**;
- tags;
- versioned schema migrations.

The interface is built around one idea from security printing: every file version gets a **custody seal** generated from its SHA-256. Around it are:
- role dashboards and an owner activity feed;
- download receipts;
- an admin console with a 14-day allowed/refused chart and an audit-chain explorer;
- a command palette, drag-and-drop upload and dark mode.

All of it is served under a strict CSP with no inline code.

It ships with 130 automated tests and a mutation check that removes 47 security checks one at a time and shows the tests fail for each.

### Attacking my own finished system

After building everything, I attacked it:
- a fuzzer over all 51 routes;
- hand-written attacks;
- an automatic sweep that removes every authorisation check.

The fuzzer found nothing. The hand-written attacks found three real holes:
1. Readers could download the **unredacted original** through `?version=1`.
2. The admin could **recover a salary letter's contents from the SHA-256 in the audit trail** by guessing.
3. `HEAD` requests wrote **false download records**.

They also found an existence oracle and two crashes. All are fixed and tested (THREATS.md section PT). I include them because they are exactly the kind of thing a test suite written by the same person who wrote the code does not catch.

### What changed in the second iteration, and why

I attacked my own first version the way a judge would and found two real holes:

1. **A demoted owner could still share** their documents (AC-12).
2. **One judge could lock everyone else out** of the shared demo accounts by resetting a password as admin (OP-10).

Both are fixed and tested. I also replaced three "accepted" or "argued" entries with tested controls:

- the check-then-act race (AC-11);
- the lack of MFA (AN-7);
- reactivated leavers getting their access back (RV-11).

The other additions answer the brief's open questions about leavers, deletion and retention, and what an owner should be able to see.

## My permission model, in my own words

> *Interview tip: rewrite this section in your own words once you have read `app/authz.py`. You will be asked to explain it without notes.*

A document has exactly one **owner**, the person who uploaded it. The owner can give a named person **read** (open and download) or **edit** (also change details and upload new versions) access, and can set an end date on it. Only the owner can share, revoke, delete, restore or see the document's record. People with edit access cannot pass access on.

One rule about roles: **role never grants access to a document, it can only take the ability to widen access away.** Sharing, restoring, upgrading someone to edit, or extending an expiry needs both document ownership *and* the owner role. Revoking, downgrading and deleting need ownership alone, so an owner who is demoted can still clean up but can no longer hand documents out.

That is the whole model. There are no folders, no groups, no inheritance, and no "everyone in Finance". The brief's first failure story is someone being given a folder to see one file and getting forty. With no folders, that cannot happen. The cost is that sharing ten documents with someone takes ten grants. I chose to pay that cost, and I added suggestions to soften it.

**Roles decide what you can do to the system, not which documents you can read.**

- An *owner* can create documents.
- A *viewer* can only work with what was shared with them.
- An *administrator* manages accounts and watches the audit trail, but holds no access to any document's content. The function that decides document access never looks at the role.

Admins can see document titles and owners, because overseeing sharing is impossible without them, and they can transfer ownership when someone leaves, but never to themselves.

The single decision point is `authorize(document_id, action)` in `app/authz.py`. Every route that takes a document id calls it first. It reads the document and the caller's grant from the database on every request, which is why revoking access works on the very next request. Nothing that carries permission is ever issued to the browser: no signed links, no tokens with roles in them.

## Design decisions and what they cost

| Decision | Why | Cost |
|---|---|---|
| Per-document grants only | No inheritance means no accidental over-sharing. Every grant is auditable as one row. | More clicks to share many files. |
| Re-check permissions on every request; no signed URLs | Revocation is immediate, and that is provable. | A DB lookup per request. Cannot offload files to a CDN or object storage with pre-signed URLs. |
| Files encrypted inside the database | No filesystem path or bucket URL exists to guess or misconfigure. A DB copy without the key reveals nothing. | The DB grows with files. A 10 MB limit keeps it reasonable. Large-file support would need object storage plus a streaming proxy. |
| SQLite | One file, transactional, and `BEGIN IMMEDIATE` serialises writers, which keeps the audit chain gapless without extra machinery. Free hosting. | One server. The next step would be Postgres, with the same schema and an advisory lock for the chain. |
| HMAC chain plus DB triggers plus an outside witness (stdout logs and exports) | Triggers stop casual edits. The keyed chain catches edits by anyone without the key. The witness catches tail truncation, which a chain alone cannot see. | Detection, not prevention, against someone who owns the server. |
| Return 404 for "not yours" | Document ids cannot be probed. | Slightly less helpful errors for users who mistype. |
| Rule-based suggestions, not an LLM | No confidential titles or sharing data leave the system. The reason fits in one sentence the owner can check. | Less clever suggestions. |
| Server-rendered JSON API plus a small vanilla JS UI under a strict CSP | Nothing to bundle, and no `innerHTML` with user data. | A plainer UI. |

## What I deliberately did not build

- **Public or external share links.** They are the classic "the link still works after they left" failure. External partners get a normal account with a viewer role (the demo includes one), so they can be deactivated and their access is audited like anyone else's.
- **Folders, groups and inheritance.** Explained above.
- **Rendering Office files or PDFs in the browser.** Rendering user files on our origin is an XSS surface. Only a small, safe set is shown in the app: plain text, Markdown and CSV are built from DOM text nodes (never HTML), and PNG/JPEG go through a `blob:` URL that the CSP allows for images only. Everything else downloads as an attachment, and every in-app view is audited like a download, with `purpose: view`.
- **An LLM.** Explained above.
- **Mandatory MFA and a QR code.** MFA is opt-in so the shared demo works for judges. Making it mandatory per role is a small policy change (AN-12, AN-13).
- **Antivirus scanning and SSO.** Not possible to do well in a week.
- **Access requests** ("ask the owner for access"). A requester would need to know the document exists, which is exactly what 404-for-strangers hides.

## How I used AI, and where it was wrong

See [PROMPTS.md](PROMPTS.md) for dated entries. In summary, the places where the generated code was confidently wrong were all in security-relevant spots:

- an operator-precedence bug in the alert SQL;
- denial records that would be rolled back with the transaction;
- a test that assumed a hash chain detects tail deletion;
- mutation "kills" that came from crashes rather than assertions;
- dev keys that changed per process.

## What is unfinished

- MFA is optional, not enforced for any role (AN-12). Login lockout can be used to annoy a known user (AN-1b).
- Tail truncation of the audit log is detected only if someone keeps exports or reads the platform logs (AU-2b).
- An administrator can still take over an account by resetting both password and MFA. It is flagged, not prevented (AC-3b).
- The PDF active-content check is pattern based and can be evaded by obfuscation (UP-3). There is no malware scanning.
- Login IP throttling is per worker process (in memory). The per-account lockout is shared.
- The UI is functional, not polished. There is no bulk sharing or bulk download.
