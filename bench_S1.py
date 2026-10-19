"""Phase 8 deterministic security benchmark harness.

Offline, deterministic benchmark for Agent44 (Phase 8). Reuses the existing
corpus, policy engine, proxy, and observation infrastructure instead of
competing with a new framework.

Structure
---------
* ``GROUP_A`` development corpus: the exact development-partition scenarios of
  the versioned evaluation corpus (``src/agent44/corpus.py``), selected by an
  explicit, pre-declared, coverage-driven id list.
* ``GROUP_B`` Phase 7 synthetic extension suite: a small, development-only set
  of scenarios that exercise the delegation and cross-call provenance-transfer
  capabilities added in Phase 7. The existing corpus contains no dedicated
  cases for those capabilities, so these scenarios are added explicitly, with
  synthetic provenance labelled in every record (``synthetic_provenance``).

Profiles
--------
* ``baseline``: the deterministic rules-only configuration (the evaluation
  policy, enforcement disabled). Legacy behaviour; no delegation, provenance,
  or transfer tiers are active.
* ``enforcement``: the same evaluation policy with
  ``provenance.enforcement=required``, ``delegation.enforcement=required`` and
  a permissive active delegation manifest, plus the configured transfer
  resource bounds. The extension suite exercises the new capabilities only
  under this configuration.

The benchmark is deterministic and offline. It never performs model inference,
network access, or any remote service call.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent44 import corpus as corpus_module
from agent44.corpus import CORPUS_VERSION, VALID_EXPECTED, VALID_LABELS
from agent44.policy import PolicyEngine
from agent44.delegation import (
    DelegationConfig,
    DelegationContext,
    DelegationStatus,
    DelegationValidationError,
    DelegationSource,
    Principal,
    parse_delegation_manifest,
)
from agent44.transfer import (
    ProvenanceRegistry,
    ProvenanceTransferStore,
    TransferConfig,
    TransferError,
    TrustClass,
)

# --------------------------------------------------------------------------- #
# Repository layout assumptions
# --------------------------------------------------------------------------- #

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SRC_DIR = REPO_ROOT / "src" / "agent44"
EVAL_DIR = REPO_ROOT / "evaluation"
PROTOCOL_V1 = EVAL_DIR / "PROTOCOL_v1.md"
PIPELINE_PLAN = EVAL_DIR / "PILOT_PLAN_4f.6_v1.md"
PHASE8_RUN_ROOT = Path("D:/Agent44Phase8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()
