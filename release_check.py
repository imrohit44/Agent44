"""Offline Phase 9 release-check workflow.

Run with:  python release_check.py

Checks: assemble.py produces no unexpected changes, full pytest passes,
ruff output matches pre-existing baseline, packaging/import sanity, and
frozen-file hashes unchanged. No network, no vendor calls, fully offline.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BASELINE_RUFF = ROOT / ".ruff_baseline.json"
FROZEN_HASHES = ROOT / ".phase9_start_hashes.txt"


def run(cmd, *, check=True):
    print(f"$ {' '.join(cmd)}", flush=True)
    return subprocess.run(cmd, cwd=ROOT, check=check, capture_output=True, text=True)


def hash_directory(directory):
    result = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            result[str(path.relative_to(directory))] = digest
    return result


def step1_assemble():
    print("=== Step 1: assemble.py ===")
    before = hash_directory(ROOT / "src" / "agent44")
    result = run([sys.executable, "assemble.py"], check=False)
    after = hash_directory(ROOT / "src" / "agent44")
    if before != after:
        print("FAIL: assemble.py changed files under src/agent44/")
        return False
    if result.returncode != 0:
        print("FAIL: assemble.py exited non-zero")
        print(result.stdout)
        print(result.stderr)
        return False
    print("PASS: assemble.py produced no changes and exited 0")
    return True


def step2_pytest():
    print("=== Step 2: pytest ===")
    result = run([sys.executable, "-m", "pytest", "tests/", "-q"], check=False)
    if result.returncode != 0:
        print("FAIL: pytest failed")
        print(result.stdout[-3000:])
        print(result.stderr[-3000:])
        return False
    for line in result.stdout.splitlines():
        if "passed" in line or "failed" in line:
            print(line.strip())
    print("PASS: all tests passed")
    return True


def step3_ruff_diff():
    print("=== Step 3: ruff diff ===")
    result = run([sys.executable, "-m", "ruff", "check", "src/", "tests/"], check=False)
    current_output = result.stdout + result.stderr
    if BASELINE_RUFF.exists():
        baseline = BASELINE_RUFF.read_text()
    else:
        print("  (no baseline; creating one from current output)")
        BASELINE_RUFF.write_text(current_output)
        print("PASS: baseline created (first run)")
        return True
    if current_output == baseline:
        print("PASS: ruff output matches pre-existing baseline (no new issues)")
        return True
    print("FAIL: ruff output differs from pre-existing baseline")
    print("--- baseline ---")
    print(baseline[:2000])
    print("--- current ---")
    print(current_output[:2000])
    return False


def step4_packaging_import():
    print("=== Step 4: packaging/import sanity ===")
    modules = [
        "agent44",
        "agent44.policy",
        "agent44.proxy",
        "agent44.delegation",
        "agent44.provenance",
        "agent44.transfer",
        "agent44.model_adapter",
        "agent44.observe",
        "agent44.threshold_adapter",
        "agent44.argument_policy",
    ]
    for mod in modules:
        try:
            __import__(mod)
        except Exception as exc:
            print(f"FAIL: import {mod} raised {exc}")
            return False
    print("PASS: all agent44 modules import cleanly")
    result = run(
        [sys.executable, "-c", "import agent44.threshold_adapter; print('import OK')"],
        check=False,
    )
    if result.returncode != 0:
        print("FAIL: clean interpreter import failed")
        print(result.stderr)
        return False
    print("PASS: clean interpreter import OK")
    return True


def step5_frozen_hashes():
    print("=== Step 5: frozen-file hashes ===")
    if not FROZEN_HASHES.exists():
        print("SKIP: .phase9_start_hashes.txt not found")
        return True
    expected = {}
    raw = FROZEN_HASHES.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16")
    else:
        text = raw.decode("utf-8", errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            expected[parts[1]] = parts[0]
    mismatches = []
    for rel_path, expected_hash in expected.items():
        full_path = ROOT / rel_path
        if not full_path.exists():
            mismatches.append(f"MISSING: {rel_path}")
            continue
        actual = hashlib.sha256(full_path.read_bytes()).hexdigest()
        if actual != expected_hash:
            mismatches.append(f"CHANGED: {rel_path}")
    if mismatches:
        print("FAIL: frozen-file hashes changed:")
        for m in mismatches:
            print(f"  {m}")
        return False
    print(f"PASS: {len(expected)} frozen-file hashes unchanged")
    return True


def main():
    steps = [
        ("assemble.py no unexpected changes", step1_assemble),
        ("full pytest", step2_pytest),
        ("ruff diff vs baseline", step3_ruff_diff),
        ("packaging/import sanity", step4_packaging_import),
        ("frozen-file hashes", step5_frozen_hashes),
    ]
    passed = 0
    failed = 0
    for name, step in steps:
        print()
        try:
            ok = step()
        except Exception as exc:
            print(f"FAIL: {name} raised {exc}")
            ok = False
        if ok:
            passed += 1
        else:
            failed += 1
            print(f"  >> {name}: FAILED")
    print()
    print("=" * 50)
    print(f"Release check: {passed} passed, {failed} failed out of {len(steps)}")
    print("RELEASE CHECK: " + ("FAILED" if failed else "PASSED"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())