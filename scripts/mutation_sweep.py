"""Exhaustive version of the judges' test: remove EVERY authorisation check, one
at a time, and prove the test suite fails each time.

    python -m scripts.mutation_sweep

Unlike scripts/mutation_check.py (hand-picked mutants with descriptions), this
finds the checks automatically, so a check added later is covered without
anyone remembering to list it:

  * every `authorize(<id>, "<action>")` call in app/routes/  -> replaced by a
    lookup that returns the document with full 'owner' access and no checks;
  * every `@login_required` and `@roles_required(...)` decorator in app/routes/
    -> deleted.

Exit code 1 if any mutant survives.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROUTES = os.path.join("app", "routes")

BYPASS = '''

def _mutant_bypass(document_id, action=None):
    """Injected by mutation_sweep: no checks at all."""
    doc = get_db().execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
    if doc is None:
        raise ApiError(404, "Document not found.")
    g.doc_level = "owner"
    return doc
'''

CALL = re.compile(r'\bauthorize\(')
DECORATOR = re.compile(r'^\s*@(login_required|recent_auth|roles_required\([^)]*\))\s*$')


def find_mutants():
    mutants = []
    for name in sorted(os.listdir(os.path.join(ROOT, ROUTES))):
        if not name.endswith(".py"):
            continue
        rel = os.path.join(ROUTES, name)
        lines = open(os.path.join(ROOT, rel), encoding="utf-8").read().splitlines()
        for i, line in enumerate(lines):
            code = line.split("#", 1)[0].strip()
            # a real call: authorize(<expr>, "<action>")  - not prose in a docstring
            is_call = re.match(r'^(doc = )?authorize\([^()]*(\[[^\]]*\])?[^()]*,\s*"[a-z_]+"\)', code) is not None
            if is_call:
                mutants.append(("authorize", rel, i, line.strip()))
            elif DECORATOR.match(line):
                func = next((l.strip() for l in lines[i + 1:i + 4] if l.strip().startswith("def ")), "?")
                mutants.append(("decorator", rel, i, f"{line.strip()} on {func}"))
    return mutants


def apply(repo, kind, rel, idx):
    path = os.path.join(repo, rel)
    lines = open(path, encoding="utf-8").read().splitlines()
    if kind == "decorator":
        del lines[idx]
    else:
        lines[idx] = CALL.sub("_mutant_bypass(", lines[idx], count=1)
        # make the bypass importable from the route module
        for j, l in enumerate(lines):
            if l.startswith("from ..authz import"):
                lines.insert(j + 1, "from ..authz import _mutant_bypass  # mutant")
                break
        with open(os.path.join(repo, "app", "authz.py"), "a", encoding="utf-8") as f:
            f.write(BYPASS)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def run(m):
    kind, rel, idx, label = m
    work = tempfile.mkdtemp(prefix="tv-sweep-")
    try:
        repo = os.path.join(work, "repo")
        shutil.copytree(ROOT, repo, ignore=shutil.ignore_patterns(".git", "instance", "__pycache__", "*.db*", ".venv", "venv"))
        apply(repo, kind, rel, idx)
        p = subprocess.run([sys.executable, "-W", "ignore", "-m", "unittest", "discover", "-s", "tests", "-t", "."],
                           cwd=repo, capture_output=True, text=True, timeout=900)
        tail = p.stderr.strip().splitlines()[-1] if p.stderr.strip() else ""
        return m, ("killed" if p.returncode else "SURVIVED"), tail
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    mutants = find_mutants()
    print(f"Removing each of {len(mutants)} authorisation checks in turn...\n")
    with ThreadPoolExecutor(max_workers=int(os.environ.get("MUTATION_WORKERS", "4"))) as pool:
        results = list(pool.map(run, mutants))
    bad = 0
    for (kind, rel, idx, label), status, tail in results:
        print(f"{status:<8} {rel}:{idx + 1:<4} {label[:90]}  [{tail}]")
        bad += status != "killed"
    print(f"\n{len(results) - bad}/{len(results)} removed checks were caught by the tests.")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
