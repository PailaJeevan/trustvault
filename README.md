# TrustVault

Secure document sharing with a real audit trail. A document can be reached only by someone it was granted to, by name. Taking access away works on the next request. Every access is recorded, including the refused ones, in a hash-chained log that cannot be quietly altered.

**Live demo:** https://trustvault-15td.onrender.com (Render free plan: it sleeps after 15 minutes idle, so the first visit can take about a minute, and it resets to the demo data when it wakes. Sign-in details are in the table below.)

**Source code:** https://github.com/PailaJeevan/trustvault

**Stack:** Python 3.11+ · Flask · SQLite · `cryptography` (AES-256-GCM). Three dependencies. No front-end framework.

## The interface

- **Custody seals.** Every file version gets a seal: a guilloche rosette generated from its SHA-256, the way banknotes use security printing. The same file always draws the same seal, and one changed byte draws a different one. The full hash is always shown beside it.
- **Overview dashboard** for each role, an **activity feed** with an unread badge ("who opened, downloaded or was refused on my documents"), and **download receipts** that tell you which audit record logged your download.
- **Admin console:**
  - a 14-day chart of allowed versus refused events;
  - a live **audit-integrity seal** with re-verify;
  - an **integrity chain explorer** showing how each record links to the one before;
  - the most-refused people;
  - alerts, people and documents.
- **Usability:**
  - a **command palette** (Ctrl/⌘ K or `/`);
  - drag-and-drop upload with checks before sending and a progress bar;
  - card and table views;
  - sharing with expiry presets;
  - an access review with filters;
  - light and dark themes;
  - fully responsive;
  - keyboard and screen-reader friendly.
- **Newer additions:**
  - a **safe in-app viewer** for text, Markdown, CSV and images; every view is recorded in the custody record as a receipt (`purpose=view`);
  - a **sharing timeline** showing when each person's access starts and ends, plus "Your access ends in N days" chips for people it was shared with;
  - a **30-day custody chart** on every document;
  - an **access map** (people × documents grid) in the access review, with click-to-select bulk revoke;
  - **multi-file upload** (up to 20) with per-file checks and progress;
  - a **step-up password prompt** before sensitive actions, and an **Approvals** tab for the two-person rule;
  - a live notification badge and **keyboard shortcuts** (`?` lists them; `g` then `d`/`u`/`r`/`a` to jump).
- **No inline styles or scripts.** The strict Content-Security-Policy (`default-src 'self'`) stays intact, and the fonts (Roboto Slab, Lato) are bundled locally.

## Demo accounts

| Role | Email | Password | What to try |
|---|---|---|---|
| Administrator | `jeevan@trustvault.test` | `Admin_123_demo` | Alerts, audit trail, users. You **cannot** open anyone's documents. |
| Second administrator | `admin2@trustvault.test` | `Arjun-Demo-2026!` | Approves what the first admin requests (two-person rule: Administration → Approvals). |
| Owner | `advik@trustvault.test` | `Owner1_123_demo` | Owns the salary letters, financials and partner contract. Share, revoke, view the custody record. |
| Owner | `vidya@trustvault.test` | `Owner2_123_demo` | Owns the engineering and audit papers, plus private notes nobody else can read. |
| Viewer | `akhilesh@trustvault.test` | `Viewer1_123_demo` | Can read his own salary letter, edit the Q3 financials, and read the audit papers. |
| Viewer | `akhil@trustvault.test` | `Viewer2_123_demo` | Can read his own salary letter and edit the bridge drawings. Nothing else. |
| Viewer (external) | `ext@partner.test` | `Partner-Demo-2026!` | An outside partner. Can read the partner contract and nothing else. |
| Owner with **two-step sign-in** | `maya@trustvault.test` | `Maya-Demo-2026!` + a code | Add the setup key `JBSWY3DPEHPK3PXPTRUSTVAULTDEMO22` to any authenticator app (Google or Microsoft Authenticator: "Enter a setup key", time-based), or run `oathtool --totp -b JBSWY3DPEHPK3PXPTRUSTVAULTDEMO22`. The key is public on purpose, for the demo only. |

While `TV_DEMO_MODE=1`, nobody can change the password or sign-in settings of the shared demo accounts, **including the admin**, so one judge cannot lock the others out. Deactivating a user and changing a role stay allowed so you can test revocation; please undo them afterwards. To try password reset, MFA enrolment or offboarding, create your own account under Administration → Users. To restore the demo data, run `python -m scripts.seed --reset`.

## Roles

| | Administrator | Owner | Viewer |
|---|---|---|---|
| Upload new documents | – | ✓ | – |
| Share, restore, upgrade or extend access (**widening**) | – | own documents only | – |
| Open or download a document | only if granted | own, or if granted | only if granted |
| Edit a document / upload a new version | only with an edit grant | own, or with an edit grant | only with an edit grant |
| Revoke, downgrade, delete, see a document's record (**narrowing**) | – | own documents (also after being demoted) | – |
| Access review across all your documents, with bulk revoke | – | ✓ | – |
| Two-step sign-in, see and end your own sessions | ✓ | ✓ | ✓ |
| Search the people directory | ✓ | ✓ | – |
| Manage accounts, see all audit records and alerts | ✓ | – | – |
| See document **metadata** for everything | ✓ | – | – |
| Transfer ownership (for leavers) | ✓, never to themselves | – | – |
| Offboard a leaver, reset someone's two-step sign-in | ✓ | – | – |
| Place or release a legal hold | ✓ (gives no access) | – | – |

The full permission model is explained in [WRITEUP.md](WRITEUP.md), the threats and controls in [THREATS.md](THREATS.md), and every endpoint with who may call it in [API.md](API.md).

## Run it locally (from a clean clone)

```bash
git clone https://github.com/PailaJeevan/trustvault.git
cd trustvault
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m scripts.seed               # creates instance/trustvault.db with demo data
python wsgi.py                       # http://127.0.0.1:5000
```

In development the app generates its keys into `instance/dev_keys.json`. In production (`TV_ENV=production`) it refuses to start unless `TV_MASTER_KEY` and `TV_AUDIT_KEY` are set.

## Tests

```bash
python -m unittest discover -s tests -t . -v    # 187 tests, about 30 seconds
python -m scripts.mutation_check                # removes 67 named security checks one at a time
python -m scripts.mutation_sweep                # removes EVERY authorize() call and auth decorator, one at a time
python -m scripts.check_live https://trustvault-15td.onrender.com  # 48 checks against the live site
```

The mutation check copies the repo, disables one check, such as the `authorize()` line in the download handler, and confirms that the suite fails. Expect `67/67 mutants killed` and `85/85 removed checks were caught`. See THREATS.md section **PT** for what attacking the finished system found. Test names map to the IDs in THREATS.md.

## Database

The base schema is in [`app/schema.sql`](app/schema.sql), and later changes are in [`app/migrations.py`](app/migrations.py). Both are applied automatically on start: a new database gets the schema plus every migration, and an existing one is upgraded in place. The seed script is `scripts/seed.py`.

**Backup:**

```bash
sqlite3 "$TV_DATABASE_PATH" ".backup backup-$(date +%F).db"
```

Store the backup and `TV_MASTER_KEY` separately. Neither one is useful without the other.

## Deploy

The live demo runs on **Render** at https://trustvault-15td.onrender.com, built from the `Dockerfile` by the Blueprint in `render.yaml`. Every push to `main` redeploys it. Step-by-step instructions, the settings it uses and a troubleshooting table are in **[DEPLOY.md](DEPLOY.md)**, which also covers PythonAnywhere and other Docker hosts.

Prove the live site holds:

```bash
python -m scripts.check_live https://trustvault-15td.onrender.com  # 48 checks against the live site
```

It is on Render's free plan, so the server sleeps after 15 minutes without visitors, and the data, including the audit trail, resets to the demo data when it wakes (THREATS.md OP-17).

## Verify the audit trail

- In the app: **Administration → Alerts** shows the integrity status of the whole chain.
- From a console: `python -m scripts.verify_audit`
- Against an earlier export: `python -m scripts.verify_audit --against export.jsonl`

## Hand-in map

| Required | Where |
|---|---|
| Threat model | [THREATS.md](THREATS.md) |
| AI usage log | [PROMPTS.md](PROMPTS.md) |
| Tests | [`tests/`](tests) and [`scripts/mutation_check.py`](scripts/mutation_check.py) |
| Schema and setup | [`app/schema.sql`](app/schema.sql), [`scripts/seed.py`](scripts/seed.py), this README |
| API documentation | [API.md](API.md) |
| Write-up | [WRITEUP.md](WRITEUP.md) |
| Demo video | [`LINK-TO-VIDEO`](https://github.com/PailaJeevan/trustvault/blob/main/TrustVault-Demo.mp4) |
