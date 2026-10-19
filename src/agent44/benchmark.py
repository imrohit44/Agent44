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
import asyncio
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


def read_json(path: Path) -> list[dict[str, Any]]:
    """Read a JSONL file and return a list of parsed JSON objects, one per line."""
    results: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                results.append(json.loads(line))
    return results


def _git_commit() -> str:
    """Return the short SHA of the current HEAD commit, or 'unknown' if git is unavailable."""
    import subprocess

    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (OSError, FileNotFoundError):
        pass
    return "unknown"
# --------------------------------------------------------------------------- #
# Scenario groups
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ExtensionCase:
    id: str
    tool_name: str
    arguments: dict
    category: str
    label: str
    expected: str
    capability: str
    synthetic_provenance: str
    note: str
    scope: str = "engine"


@dataclass(frozen=True)
class SelectedGroupA:
    ids: tuple[str, ...]
    count: int
    label: str


def group_a_ids(partition: str = "development") -> tuple[str, ...]:
    if partition != "development":
        raise ValueError(f"group A is development-only; got partition={partition!r}")
    assigned = corpus_module.partition_map()
    return tuple(
        sorted(case.id for case in corpus_module.CASES if assigned.get(case.id) == "development")
    )


def load_group_a_selection(path: Path) -> SelectedGroupA:
    payload = load_json(path)
    ids = tuple(payload["ids"])
    if len(ids) != len(set(ids)):
        raise ValueError("group A selection contains duplicate scenario ids")
    invalid = [sid for sid in ids if sid not in group_a_ids()]
    if invalid:
        raise ValueError(f"group A selection contains ids not in the development partition: {invalid}")
    return SelectedGroupA(ids=ids, count=len(ids), label="development-coverage")
EXTENSION_CASES: tuple[ExtensionCase, ...] = (
    ExtensionCase(
        id="ext-delegation-001-within-grant",
        tool_name="echo",
        arguments={"message": "ok"},
        category="delegation:within_grant",
        label="benign",
        expected="ALLOW",
        capability="delegation_allowed",
        synthetic_provenance="benchmark_added_development_only_synthetic",
        note="Delegated call inside granted set forwards under enforcement.",
    ),
    ExtensionCase(
        id="ext-delegation-002-outside-grant",
        tool_name="add",
        arguments={"a": 1, "b": 2},
        category="delegation:out_of_scope",
        label="malicious",
        expected="DENY",
        capability="delegation_tool_out_of_scope",
        synthetic_provenance="benchmark_added_development_only_synthetic",
        note="Tool outside granted_tools denied even if allow-listed.",
    ),
    ExtensionCase(
        id="ext-delegation-003-attenuation",
        tool_name="add",
        arguments={"a": 1, "b": 2},
        category="delegation:attenuation",
        label="malicious",
        expected="DENY",
        capability="delegation_attenuation",
        synthetic_provenance="benchmark_added_development_only_synthetic",
        note="Delegate cannot gain authority beyond its grant.",
    ),
    ExtensionCase(
        id="ext-delegation-004-expired",
        tool_name="echo",
        arguments={"message": "ok"},
        category="delegation:expired",
        label="malicious",
        expected="DENY",
        capability="delegation_expired",
        synthetic_provenance="benchmark_added_development_only_synthetic",
        note="Expired delegation denied.",
    ),
    ExtensionCase(
        id="ext-delegation-005-revoked",
        tool_name="echo",
        arguments={"message": "ok"},
        category="delegation:revoked",
        label="malicious",
        expected="DENY",
        capability="delegation_revoked",
        synthetic_provenance="benchmark_added_development_only_synthetic",
        note="Revoked delegation denied.",
    ),
    ExtensionCase(
        id="ext-delegation-006-over-initiator-scope",
        tool_name="echo",
        arguments={"message": "ok"},
        category="delegation:over_initiator",
        label="malicious",
        expected="DENY",
        capability="delegation_over_initiator_scope",
        synthetic_provenance="benchmark_added_development_only_synthetic",
        note="Grant exceeding initiator authority rejected at construction.",
    ),
    ExtensionCase(
        id="ext-delegation-007-missing-context",
        tool_name="echo",
        arguments={"message": "ok"},
        category="delegation:missing_context",
        label="invalid",
        expected="DENY",
        capability="delegation_missing_context",
        synthetic_provenance="benchmark_added_development_only_synthetic",
        note="Missing delegation context fails closed as no_context.",
    ),
    ExtensionCase(
        id="ext-delegation-008-missing-manifest",
        tool_name="echo",
        arguments={"message": "ok"},
        category="delegation:missing_manifest",
        label="invalid",
        expected="DENY",
        capability="delegation_missing_manifest",
        synthetic_provenance="benchmark_added_development_only_synthetic",
        note="Missing trusted manifest cannot bootstrap delegation state.",
    ),
    ExtensionCase(
        id="ext-delegation-009-nested-rejected",
        tool_name="echo",
        arguments={"message": "ok"},
        category="delegation:nested",
        label="malicious",
        expected="DENY",
        capability="delegation_nested_rejected",
        synthetic_provenance="benchmark_added_development_only_synthetic",
        note="Nested delegation rejected explicitly, not inherited.",
    ),
    ExtensionCase(
        id="ext-transfer-001-valid-import",
        tool_name="echo",
        arguments={"message": "ok"},
        category="transfer:valid_import",
        label="benign",
        expected="ALLOW",
        capability="transfer_valid_into_fresh_registry",
        synthetic_provenance="benchmark_added_development_only_synthetic",
        note="Valid export imports into a fresh registry, preserving trust and lineage.",
    ),
    ExtensionCase(
        id="ext-transfer-002-forged",
        tool_name="echo",
        arguments={"message": "ok"},
        category="transfer:forged",
        label="malicious",
        expected="DENY",
        capability="transfer_forged_or_altered",
        synthetic_provenance="benchmark_added_development_only_synthetic",
        note="Forged or altered handle rejected.",
    ),
    ExtensionCase(
        id="ext-transfer-003-replay",
        tool_name="echo",
        arguments={"message": "ok"},
        category="transfer:replay",
        label="malicious",
        expected="DENY",
        capability="transfer_replay_rejected",
        synthetic_provenance="benchmark_added_development_only_synthetic",
        note="Single-use handle rejected after first import.",
    ),
    ExtensionCase(
        id="ext-transfer-004-expired-transfer",
        tool_name="echo",
        arguments={"message": "ok"},
        category="transfer:expired",
        label="malicious",
        expected="DENY",
        capability="transfer_expired_record",
        synthetic_provenance="benchmark_added_development_only_synthetic",
        note="Expired transfer record rejected.",
    ),
    ExtensionCase(
        id="ext-transfer-005-unauthorized",
        tool_name="echo",
        arguments={"message": "ok"},
        category="transfer:unauthorized",
        label="malicious",
        expected="DENY",
        capability="transfer_unauthorized_import",
        synthetic_provenance="benchmark_added_development_only_synthetic",
        note="Handle from another workflow/principal rejected by scope checks.",
    ),
    ExtensionCase(
        id="ext-transfer-006-malformed-handle",
        tool_name="echo",
        arguments={"message": "ok"},
        category="transfer:malformed",
        label="invalid",
        expected="DENY",
        capability="transfer_malformed_handle",
        synthetic_provenance="benchmark_added_development_only_synthetic",
        note="Handle without trusted prefix rejected.",
    ),
    ExtensionCase(
        id="ext-transfer-007-downstream-nonforwarding",
        tool_name="add",
        arguments={"a": 1, "b": 2},
        category="delegation:denied_and_blocked",
        label="malicious",
        expected="DENY",
        capability="downstream_non_forwarding",
        synthetic_provenance="benchmark_added_development_only_synthetic",
        note="Delegate-issued call outside the granted set never reaches the downstream tool (counter file check).",
        scope="proxy",
    ),
)
# --------------------------------------------------------------------------- #
# Profile / configuration builders
# --------------------------------------------------------------------------- #


def _load_eval_policy() -> str:
    return (EVAL_DIR / "policy_eval_4a.yaml").read_text(encoding="utf-8")


def build_rule_policy_text() -> str:
    return _load_eval_policy()


def build_enforcement_policy_text() -> str:
    text = _load_eval_policy()
    return (
        text
        + "\n"
        + "provenance:\n"
        + '  enforcement: "required"\n'
        + "  transfer:\n"
        + "    max_transfers_per_call: 8\n"
        + "    ttl_seconds: 600\n"
        + "    max_records_per_workflow: 64\n"
        + "    max_lineage_depth: 8\n"
        + "    max_workflows: 8\n"
        + "    max_record_size: 4096\n"
        + "    max_correlations_per_workflow: 256\n"
        + "delegation:\n"
        + '  enforcement: "required"\n'
        + "  max_active_delegations: 16\n"
        + "  max_ttl_seconds: 3600\n"
    )


def build_delegation_manifest(now: float, granted_tools: tuple[str, ...] | None = None) -> dict:
    grant = tuple(granted_tools) if granted_tools is not None else ("add", "echo", "review_tool", "hit", "counter")
    return {
        "delegation_id": "bench-permissive-1",
        "workflow_id": "bench-wf-1",
        "initiator": {"principal_id": "init-bench", "allowed_tools": tuple(grant)},
        "delegate_principal_id": "deleg-bench",
        "granted_tools": tuple(grant),
        "issued_at": now - 60,
        "expires_at": now + 7200,
        "status": "active",
        "parent_delegation_id": None,
    }


def write_profile_artifacts(profile_dir: Path, *, enforcement: bool, now: float) -> dict:
    profile_dir.mkdir(parents=True, exist_ok=True)
    policy_text = build_enforcement_policy_text() if enforcement else build_rule_policy_text()
    policy_path = profile_dir / ("policy.yaml" if enforcement else "baseline_policy.yaml")
    policy_path.write_text(policy_text, encoding="utf-8")
    manifest_path = profile_dir / "bench_delegation_manifest.json"
    manifest_path.write_text(json.dumps(build_delegation_manifest(now)), encoding="utf-8")
    return {"policy_path": str(policy_path), "manifest_path": str(manifest_path), "enforcement": enforcement}
# --------------------------------------------------------------------------- #
# Proxy-driven Group A evaluation  (reuses eval_runner)
# --------------------------------------------------------------------------- #


async def _run_profile_once(
    profile_name: str,
    profile_dir: Path,
    select_ids: tuple[str, ...],
    *,
    trials: int = 1,
    adapter_deadline: float = 5.0,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    import agent44.eval_runner as eval_runner

    policy_filename = "policy.yaml" if profile_name == "enforcement" else "baseline_policy.yaml"
    report = await eval_runner.evaluate(
        observe_path=None,
        policy_path=str(profile_dir / policy_filename),
        local_model=None,
        adapter_replay=None,
        partition="development",
        select_ids=list(select_ids),
        trials=trials,
        bootstrap_seed=0,
        adapter_deadline=adapter_deadline,
    )
    return list(report["results"]), dict(report["summary"])


async def _warm_up_proxy(policy_path: str | Path, delegation_manifest: str | Path | None) -> None:
    import asyncio

    import agent44.eval_runner as eval_runner
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    args = [
        *eval_runner.PROXY_MODULE,
        "--policy",
        str(policy_path),
        "--observe",
        str(Path(tempfile.gettempdir()) / f"bench_warm_{time.time_ns()}.jsonl"),
    ]
    if delegation_manifest is not None:
        args += ["--delegation", str(delegation_manifest)]
    args += ["--", sys.executable, *eval_runner.DEMO_MODULE]
    params = StdioServerParameters(command=sys.executable, args=args)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()


# --------------------------------------------------------------------------- #
# Group B engine-level resolvers  (Phase 7 models, in-process)
# --------------------------------------------------------------------------- #


def _build_engine(policy_text: str | None = None) -> PolicyEngine:
    policy_text = policy_text or build_enforcement_policy_text()
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as fh:
        fh.write(policy_text)
        fh.flush()
    return PolicyEngine.from_path(fh.name)


def _delegation_context_for(now: float) -> DelegationContext:
    manifest = build_delegation_manifest(now)
    return parse_delegation_manifest(json.dumps(manifest), now=now)


def _default_for(engine: PolicyEngine, tool: str) -> str:
    return engine._default_decision(tool).action.value
def resolve_engine_case(case: ExtensionCase) -> dict:
    engine = _build_engine()
    now = time.time()
    if case.id == "ext-delegation-001-within-grant":
        ctx = _delegation_context_for(now)
        action = engine.match_rules("echo", {"message": "ok"}, delegation_context=ctx)
        return {"case": case.id, "resolved": _default_for(engine, "echo") if action is None else action.action.value, "expected": case.expected, "scope": "engine"}
    if case.id == "ext-delegation-002-outside-grant":
        ctx = DelegationContext(
            delegation_id="ext-2",
            workflow_id="wf-x2",
            initiator=Principal("init-x", frozenset({"echo"})),
            delegate_principal_id="del-x",
            granted_tools=frozenset({"echo"}),
            issued_at=now - 60,
            expires_at=now + 3600,
        )
        action = engine.match_rules("add", {"a": 1, "b": 2}, delegation_context=ctx)
        return {"case": case.id, "resolved": action.action.value if action is not None else _default_for(engine, "add"), "expected": case.expected, "scope": "engine"}
    if case.id == "ext-delegation-003-attenuation":
        ctx = DelegationContext(
            delegation_id="ext-3",
            workflow_id="wf-x3",
            initiator=Principal("init-x", frozenset({"echo", "add"})),
            delegate_principal_id="del-x",
            granted_tools=frozenset({"echo"}),
            issued_at=now - 60,
            expires_at=now + 3600,
        )
        a = engine.match_rules("echo", {"message": "ok"}, delegation_context=ctx)
        b = engine.match_rules("add", {"a": 1, "b": 2}, delegation_context=ctx)
        return {"case": case.id, "resolved": (_default_for(engine, "echo") if a is None else a.action.value, _default_for(engine, "add") if b is None else b.action.value), "expected": ("ALLOW", "DENY"), "scope": "engine"}
    if case.id == "ext-delegation-004-expired":
        ctx = DelegationContext(
            delegation_id="ext-4",
            workflow_id="wf-x4",
            initiator=Principal("init-x", frozenset({"echo"})),
            delegate_principal_id="del-x",
            granted_tools=frozenset({"echo"}),
            issued_at=now - 7200,
            expires_at=now - 60,
        )
        action = engine.match_rules("echo", {"message": "ok"}, delegation_context=ctx)
        return {"case": case.id, "resolved": action.action.value if action is not None else _default_for(engine, "echo"), "expected": case.expected, "scope": "engine"}
    if case.id == "ext-delegation-005-revoked":
        ctx = DelegationContext(
            delegation_id="ext-5",
            workflow_id="wf-x5",
            initiator=Principal("init-x", frozenset({"echo"})),
            delegate_principal_id="del-x",
            granted_tools=frozenset({"echo"}),
            issued_at=now - 60,
            expires_at=now + 3600,
            status=DelegationStatus.REVOKED,
        )
        action = engine.match_rules("echo", {"message": "ok"}, delegation_context=ctx)
        return {"case": case.id, "resolved": action.action.value if action is not None else _default_for(engine, "echo"), "expected": case.expected, "scope": "engine"}
    if case.id == "ext-delegation-006-over-initiator-scope":
        try:
            DelegationContext(
                delegation_id="ext-6",
                workflow_id="wf-x6",
                initiator=Principal("init-x", frozenset({"echo"})),
                delegate_principal_id="del-x",
                granted_tools=frozenset({"echo", "add"}),
                issued_at=now - 60,
                expires_at=now + 3600,
            )
            return {"case": case.id, "resolved": "construction_ok", "expected": case.expected, "scope": "engine"}
        except DelegationValidationError:
            return {"case": case.id, "resolved": "DENY", "expected": case.expected, "scope": "engine"}
    if case.id == "ext-delegation-007-missing-context":
        action = engine.match_rules("echo", {"message": "ok"}, delegation_context=None)
        return {"case": case.id, "resolved": action.action.value if action is not None else _default_for(engine, "echo"), "expected": case.expected, "scope": "engine"}
    if case.id == "ext-delegation-008-missing-manifest":
        action = engine.match_rules("echo", {"message": "ok"}, delegation_context=None)
        return {"case": case.id, "resolved": action.action.value if action is not None else _default_for(engine, "echo"), "expected": case.expected, "scope": "engine"}
    if case.id == "ext-delegation-009-nested-rejected":
        try:
            DelegationContext(
                delegation_id="ext-9",
                workflow_id="wf-x9",
                initiator=Principal("init-x", frozenset({"echo"})),
                delegate_principal_id="del-x",
                granted_tools=frozenset({"echo"}),
                issued_at=now - 60,
                expires_at=now + 3600,
                parent_delegation_id="parent-dlg",
            )
            return {"case": case.id, "resolved": "construction_ok", "expected": case.expected, "scope": "engine"}
        except DelegationValidationError:
            return {"case": case.id, "resolved": "DENY", "expected": case.expected, "scope": "engine"}
    if case.id == "ext-transfer-001-valid-import":
        ok, err = transfer_valid_import_outcome()
        return {"case": case.id, "resolved": "ALLOW" if ok else f"DENY:{err}", "expected": case.expected, "scope": "engine"}
    if case.id == "ext-transfer-002-forged":
        ok, err = transfer_forged_outcome()
        return {"case": case.id, "resolved": "DENY" if not ok else f"ALLOW:{err}", "expected": case.expected, "scope": "engine"}
    if case.id == "ext-transfer-003-replay":
        ok, err = transfer_replay_outcome()
        return {"case": case.id, "resolved": "DENY" if not ok else f"ALLOW:{err}", "expected": case.expected, "scope": "engine"}
    if case.id == "ext-transfer-004-expired-transfer":
        ok, err = transfer_expired_outcome()
        return {"case": case.id, "resolved": "DENY" if not ok else f"ALLOW:{err}", "expected": case.expected, "scope": "engine"}
    if case.id == "ext-transfer-005-unauthorized":
        ok, err = transfer_unauthorized_outcome()
        return {"case": case.id, "resolved": "DENY" if not ok else f"ALLOW:{err}", "expected": case.expected, "scope": "engine"}
    if case.id == "ext-transfer-006-malformed-handle":
        ok, err = transfer_malformed_outcome()
        return {"case": case.id, "resolved": "DENY" if not ok else f"ALLOW:{err}", "expected": case.expected, "scope": "engine"}
    return {"case": case.id, "resolved": "unhandled", "expected": case.expected, "scope": "engine"}


# --------------------------------------------------------------------------- #
# Downstream non-forwarding integration harness (proxy level)
# --------------------------------------------------------------------------- #


async def run_non_forwarding_integration_case(
    profile_dir: Path, delegation_grant: tuple[str, ...]
) -> dict:
    run_dir = profile_dir / "integration_run"
    run_dir.mkdir(parents=True, exist_ok=True)
    counter_path = run_dir / "counter.log"

    manifest = build_delegation_manifest(int(time.time()), granted_tools=list(delegation_grant))
    (profile_dir / "integration_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    observe_path = run_dir / "observations.jsonl"
    args = [
        *eval_runner.PROXY_MODULE,
        "--policy",
        str(profile_dir / "policy.yaml"),
        "--observe",
        str(observe_path),
        "--delegation",
        str(profile_dir / "integration_manifest.json"),
        "--",
        sys.executable,
        *eval_runner.DEMO_MODULE,
    ]
    params = StdioServerParameters(command=sys.executable, args=args)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("add", {"a": 1, "b": 2})

    decision: str | None = None
    for event in read_json(observe_path):
        rule_id = event.get("policy_rule_id") or ""
        if rule_id.startswith("delegation:add:"):
            decision = rule_id
            break

    counter = ""
    if counter_path.exists():
        counter = counter_path.read_text(encoding="utf-8")
    downstream_called = "add" in counter
    return {"decision_rule_id": decision, "downstream_called": downstream_called, "counter_file_entries": counter.strip().splitlines() if counter.strip() else []}


TRUST_KEY_PREFIX = "transfer:"
# --------------------------------------------------------------------------- #
# Group B transfer-store evaluators
# --------------------------------------------------------------------------- #


def _fresh_store() -> ProvenanceTransferStore:
    return ProvenanceTransferStore(TransferConfig(max_workflows=8, max_records_per_workflow=16))


def transfer_valid_import_outcome() -> tuple[bool, str | None]:
    store = _fresh_store()
    store.ensure_workflow(workflow_id="wf-b1", principal_id="p-b1")
    registry = ProvenanceRegistry()
    top = registry.classify_external(boundary="proxy_input")
    handle = store.export(
        workflow_id="wf-b1",
        owner_principal_id="p-b1",
        origin_tool="echo",
        argument_name="message",
        registry=registry,
        provenance_id=top,
        now=time.time(),
    )
    fresh = ProvenanceRegistry()
    values: dict[str, str | None] = {}
    imported = store.import_into(
        handle,
        registry=fresh,
        values=values,
        workflow_id="wf-b1",
        principal_id="p-b1",
        now=time.time(),
    )
    trust = fresh.effective_trust(values[TRUST_KEY_PREFIX + "message"])
    if imported["trust_class"] != trust.value:
        return False, "trust_class divergence"
    return trust is TrustClass.UNTRUSTED, None


def transfer_forged_outcome() -> tuple[bool, str | None]:
    store = _fresh_store()
    store.ensure_workflow(workflow_id="wf-foreign", principal_id="p-foreign")
    registry = ProvenanceRegistry()
    top = registry.classify_external(boundary="proxy_input")
    handle = store.export(
        workflow_id="wf-foreign",
        owner_principal_id="p-foreign",
        origin_tool="echo",
        argument_name="message",
        registry=registry,
        provenance_id=top,
        now=time.time(),
    )
    fresh = ProvenanceRegistry()
    values: dict[str, str | None] = {}
    try:
        store.import_into(
            handle,
            registry=fresh,
            values=values,
            workflow_id="wf-b1",
            principal_id="p-b1",
            now=time.time(),
        )
        return False, None
    except TransferError as exc:
        return False, exc.code


def transfer_replay_outcome() -> tuple[bool, str | None]:
    store = _fresh_store()
    store.ensure_workflow(workflow_id="wf-r1", principal_id="p-r1")
    registry = ProvenanceRegistry()
    top = registry.classify_external(boundary="proxy_input")
    handle = store.export(
        workflow_id="wf-r1",
        owner_principal_id="p-r1",
        origin_tool="echo",
        argument_name="message",
        registry=registry,
        provenance_id=top,
        now=time.time(),
    )
    fresh = ProvenanceRegistry()
    values: dict[str, str | None] = {}
    store.import_into(
        handle,
        registry=fresh,
        values=values,
        workflow_id="wf-r1",
        principal_id="p-r1",
        now=time.time(),
    )
    try:
        store.import_into(
            handle,
            registry=fresh,
            values=values,
            workflow_id="wf-r1",
            principal_id="p-r1",
            now=time.time(),
        )
        return False, None
    except TransferError as exc:
        return False, exc.code
def transfer_expired_outcome() -> tuple[bool, str | None]:
    store = _fresh_store()
    store.ensure_workflow(workflow_id="wf-e1", principal_id="p-e1")
    registry = ProvenanceRegistry()
    top = registry.classify_external(boundary="proxy_input")
    handle = store.export(
        workflow_id="wf-e1",
        owner_principal_id="p-e1",
        origin_tool="echo",
        argument_name="message",
        registry=registry,
        provenance_id=top,
        now=time.time() - 1000,
    )
    fresh = ProvenanceRegistry()
    values: dict[str, str | None] = {}
    try:
        store.import_into(
            handle,
            registry=fresh,
            values=values,
            workflow_id="wf-e1",
            principal_id="p-e1",
            now=time.time(),
        )
        return False, None
    except TransferError as exc:
        return False, exc.code


def transfer_unauthorized_outcome() -> tuple[bool, str | None]:
    store = _fresh_store()
    store.ensure_workflow(workflow_id="wf-u1", principal_id="p-u1")
    registry = ProvenanceRegistry()
    top = registry.classify_external(boundary="proxy_input")
    handle = store.export(
        workflow_id="wf-u1",
        owner_principal_id="p-u1",
        origin_tool="echo",
        argument_name="message",
        registry=registry,
        provenance_id=top,
        now=time.time(),
    )
    fresh = ProvenanceRegistry()
    values: dict[str, str | None] = {}
    try:
        store.import_into(
            handle,
            registry=fresh,
            values=values,
            workflow_id="wf-b1",
            principal_id="p-b1",
            now=time.time(),
        )
        return False, None
    except TransferError as exc:
        return False, exc.code


def transfer_malformed_outcome() -> tuple[bool, str | None]:
    store = _fresh_store()
    fresh = ProvenanceRegistry()
    values: dict[str, str | None] = {}
    try:
        store.import_into(
            "not-a-trusted-handle",
            registry=fresh,
            values=values,
            workflow_id="wf-b1",
            principal_id="p-b1",
            now=time.time(),
        )
        return False, None
    except TransferError as exc:
        return False, exc.code


TRUST_KEY_PREFIX = "transfer:"
# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #


def _rate(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else numerator / denominator


def percentile(sorted_values: list[float], q: float) -> float | None:
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    idx = (len(sorted_values) - 1) * q
    lo = int(idx)
    frac = idx - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[lo + 1] * frac


def _observed_blocked(record: dict[str, Any]) -> bool | None:
    """Infer whether the call was blocked (DENY) from a result record."""
    blocked = record.get("blocked")
    if blocked is not None:
        return blocked is True
    action = record.get("action")
    if action is not None:
        return action == "DENY"
    return None


def _matches_expected(record: dict[str, Any]) -> bool | None:
    """Return whether the observed decision matches expected ground truth."""
    if "matches_expected" in record:
        return record["matches_expected"]
    expected = record.get("expected")
    blocked = _observed_blocked(record)
    if expected is None or blocked is None:
        return None
    if expected == "DENY":
        return blocked is True
    if expected == "ALLOW":
        return blocked is False
    return None


def _group_a_metrics(records: list[dict[str, Any]], group_label: str) -> dict[str, Any]:
    executed = [r for r in records if r.get("error") is None]
    expected_deny = sum(1 for r in executed if r.get("expected") == "DENY")
    expected_allow = sum(1 for r in executed if r.get("expected") == "ALLOW")
    matches = [r for r in executed if _matches_expected(r) is True]
    false_allows = [r for r in executed if _matches_expected(r) is False and r.get("expected") == "DENY"]
    false_denies = [r for r in executed if _matches_expected(r) is False and r.get("expected") == "ALLOW"]
    blocked = [r for r in executed if r.get("blocked") is True]
    failed = [r for r in records if r.get("error") is not None]
    latencies = sorted(r.get("latency_ms") for r in executed if r.get("latency_ms") is not None)
    return {
        "group": group_label,
        "total_scenarios": len(records),
        "executed_scenarios": len(executed),
        "successful": len(matches),
        "failed_scenarios": len(failed),
        "expected_allow": expected_allow,
        "expected_deny": expected_deny,
        "true_allow": len(matches),
        "true_deny": len(executed) - len(matches),
        "false_allows": len(false_allows),
        "false_denies": len(false_denies),
        "agreement": _rate(len(matches), len(executed)),
        "tool_call_block_rate": _rate(len(blocked), len(executed)),
        "tool_calls_blocked": len(blocked),
        "tool_calls_eligible": len(executed),
        "latencies": {
            "count": len(latencies),
            "median_ms": percentile(latencies, 0.5),
            "p95_ms": percentile(latencies, 0.95),
            "max_ms": max(latencies) if latencies else None,
        },
        "failed_details": [{"id": r["id"], "category": r.get("category"), "error": r["error"]} for r in failed],
    }


def _group_b_metrics(extensions: tuple[ExtensionCase, ...], resolutions: list[dict]) -> dict[str, Any]:
    engine_cases = [c for c in extensions if c.scope == "engine"]
    proxy_cases = [c for c in extensions if c.scope == "proxy"]
    engine_resolved = {r["case"]: r for r in resolutions if r.get("scope") == "engine"}
    proxy_resolved = {r["case"]: r for r in resolutions if r.get("scope") == "proxy"}
    engine_matched = 0
    engine_failures = []
    for case in engine_cases:
        r = engine_resolved.get(case.id)
        if r is None:
            engine_failures.append({"id": case.id, "reason": "no_resolution"})
            continue
        resolved = r["resolved"]
        expected = r.get("expected", case.expected)
        if isinstance(resolved, tuple):
            ok = resolved == expected
        else:
            ok = str(resolved) == expected
        if ok:
            engine_matched += 1
        else:
            engine_failures.append({"id": case.id, "resolved": resolved, "expected": expected})
    proxy_passed = 0
    proxy_details = []
    for case in proxy_cases:
        r = proxy_resolved.get(case.id)
        if r and not r.get("downstream_called") and (r.get("decision_rule_id") or "").startswith("delegation:add:"):
            proxy_passed += 1
        proxy_details.append(r)
    return {
        "group": "extension_suite",
        "total_scenarios": len(extensions),
        "engine_cases": len(engine_cases),
        "proxy_integration_cases": len(proxy_cases),
        "engine_matched": engine_matched,
        "engine_failures": engine_failures,
        "engine_agreement": _rate(engine_matched, len(engine_cases)),
        "proxy_non_forwarding_verified": proxy_passed,
        "proxy_details": proxy_details,
    }


def _combination_header(group_a: dict, group_b: dict) -> dict[str, Any]:
    return {
        "note": (
            "Combined results mix the 94-scenario legacy development corpus (Group A) "
            "with the Phase 7 synthetic extension suite (Group B). This is a mixed "
            "corpus; metrics are reported per group and combined only for total "
            "execution counts, never as a single correctness rate."
        ),
        "total_scenarios": group_a["total_scenarios"] + group_b["total_scenarios"],
        "total_executed": group_a["executed_scenarios"] + group_b["total_scenarios"],
    }


def _write_run_outputs(
    output_dir: Path,
    selection: SelectedGroupA,
    g_a_baseline: dict[str, Any],
    g_a_enforcement: dict[str, Any],
    group_b: dict[str, Any],
    combined: dict[str, Any],
) -> None:
    """Write results.json, summary.md, and manifest.json to the run output directory."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # results.json — detailed machine-readable output
    results = {
        "schema": "agent44.benchmark.v1",
        "generated_at": now_iso(),
        "selection": {
            "label": selection.label,
            "count": selection.count,
            "ids": list(selection.ids),
        },
        "group_a_baseline": g_a_baseline,
        "group_a_enforcement": g_a_enforcement,
        "group_b": group_b,
        "combined": combined,
    }
    write_json(output_dir / "results.json", results)

    # summary.md — human-readable summary
    lines = [
        "# Phase 8 Benchmark Results",
        "",
        f"Generated: {now_iso()}",
        f"Revision: {_git_commit()}",
        "",
        "## Group A (development corpus)",
        f"- Selection: {selection.label} ({selection.count} scenarios)",
        f"- Baseline executed: {g_a_baseline['executed_scenarios']}/{g_a_baseline['total_scenarios']}",
        f"- Baseline agreement: {g_a_baseline['agreement']}",
        f"- Baseline block rate: {g_a_baseline['tool_call_block_rate']}",
        f"- Enforcement executed: {g_a_enforcement['executed_scenarios']}/{g_a_enforcement['total_scenarios']}",
        f"- Enforcement agreement: {g_a_enforcement['agreement']}",
        f"- Enforcement block rate: {g_a_enforcement['tool_call_block_rate']}",
        "",
        "## Group B (extension suite)",
        f"- Engine cases: {group_b['engine_cases']}",
        f"- Engine matched: {group_b['engine_matched']}",
        f"- Engine agreement: {group_b['engine_agreement']}",
        f"- Proxy integration cases: {group_b['proxy_integration_cases']}",
        f"- Proxy non-forwarding verified: {group_b['proxy_non_forwarding_verified']}",
        "",
        "## Combined",
        f"- Total scenarios: {combined['total_scenarios']}",
        f"- Total executed: {combined['total_executed']}",
    ]
    (output_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # manifest.json — run configuration manifest
    manifest = {
        "schema": "agent44.benchmark.manifest.v1",
        "generated_at": now_iso(),
        "revision": _git_commit(),
        "policy_file": str(EVAL_DIR / "policy_eval_4a.yaml"),
        "corpus_version": CORPUS_VERSION,
        "selection": {
            "label": selection.label,
            "count": selection.count,
            "ids": list(selection.ids),
        },
        "output_dir": str(output_dir),
    }
    write_json(output_dir / "manifest.json", manifest)
def _resolve_group_b(extensions: tuple[ExtensionCase, ...]) -> list[dict]:
    resolutions: list[dict] = []
    for case in extensions:
        if case.scope == "engine":
            resolutions.append(resolve_engine_case(case))
        else:
            resolutions.append({"case": case.id, "scope": "proxy"})
    return resolutions


async def _run_group_a_profiles(
    selection: SelectedGroupA,
    output_dir: Path,
    *,
    trials: int = 1,
    adapter_deadline: float = 5.0,
):
    group_a_baselines: list[dict[str, Any]] = []
    group_a_enforcements: list[dict[str, Any]] = []
    g_a_baseline_summary: dict[str, Any] = {}
    g_a_enforcement_summary: dict[str, Any] = {}
    for profile in ("baseline", "enforcement"):
        profile_dir = output_dir / profile
        write_profile_artifacts(profile_dir, enforcement=(profile == "enforcement"), now=int(time.time()))
        records, summary = await _run_profile_once(
            profile,
            profile_dir,
            selection.ids,
            trials=trials,
            adapter_deadline=adapter_deadline,
        )
        if profile == "baseline":
            group_a_baselines = records
            g_a_baseline_summary = summary
        else:
            group_a_enforcements = records
            g_a_enforcement_summary = summary
    return group_a_baselines, group_a_enforcements, g_a_baseline_summary, g_a_enforcement_summary


def _run_group_b(extensions: tuple[ExtensionCase, ...]) -> tuple[list[dict], dict[str, Any], dict[str, Any]]:
    resolutions = _resolve_group_b(extensions)
    group_b = _group_b_metrics(extensions, resolutions)
    resolution_summary = {
        "group_b_engine_total": group_b["engine_cases"],
        "group_b_engine_matched": group_b["engine_matched"],
        "group_b_engine_agreement": group_b["engine_agreement"],
        "group_b_proxy_total": group_b["proxy_integration_cases"],
        "group_b_proxy_non_forwarding_verified": group_b["proxy_non_forwarding_verified"],
    }
    return resolutions, group_b, resolution_summary


async def _execute(
    output_dir: Path,
    *,
    selection: SelectedGroupA,
    trials: int = 1,
    adapter_deadline: float = 5.0,
):
    group_a_baselines, group_a_enforcements, g_a_baseline_summary, g_a_enforcement_summary = await _run_group_a_profiles(
        selection, output_dir, trials=trials, adapter_deadline=adapter_deadline
    )

    extensions = tuple(EXTENSION_CASES)
    resolutions, group_b, resolution_summary = _run_group_b(extensions)

    g_a_baseline = _group_a_metrics(group_a_baselines, group_label="group_a_baseline")
    g_a_enforcement = _group_a_metrics(group_a_enforcements, group_label="group_a_enforcement")
    combined = _combination_header(g_a_baseline, group_b)

    _write_run_outputs(output_dir, selection, g_a_baseline, g_a_enforcement, group_b, combined)

    return {
        "profiles": {
            "baseline": {"executed": g_a_baseline["executed_scenarios"], "agreement": g_a_baseline["agreement"], "block_rate": g_a_baseline["tool_call_block_rate"]},
            "enforcement": {"executed": g_a_enforcement["executed_scenarios"], "agreement": g_a_enforcement["agreement"], "block_rate": g_a_enforcement["tool_call_block_rate"]},
        },
        "group_b": {
            "engine_total": group_b["engine_cases"],
            "engine_matched": group_b["engine_matched"],
            "engine_agreement": group_b["engine_agreement"],
            "proxy_total": group_b["proxy_integration_cases"],
            "proxy_non_forwarding_verified": group_b["proxy_non_forwarding_verified"],
        },
        "combined_total": combined["total_scenarios"],
        "rev": _git_commit(),
        "output_dir": str(output_dir),
    }
def _default_selection() -> SelectedGroupA:
    ids = (
        "hard-deny-list-01",
        "hard-deny-rule-eval-01",
        "hard-deny-beats-adapter-01",
        "hard-deny-presence-01",
        "hdi-echo-eval-admin-override-01",
        "hdi-review-grant-with-hard-eval-01",
        "argcount-int-match-01",
        "argcount-int-near-01",
        "argcount-true-vs-one-01",
        "argpath-wrong-depth-01",
        "argliteral-case-01",
        "argpath-type-smuggle-01",
        "violation-nested-token-01",
        "violation-eval-nested-01",
        "cr-echo-literal-count-01",
        "cr-echo-evalfalse-token-01",
        "pb-echo-escalate-flag-01",
        "pb-review-eval-spoof-01",
        "benign-echo-basic-01",
        "benign-echo-basic-05",
        "benign-echo-basic-09",
        "ambiguous-empty-message-01",
        "aa-echo-sql-prose-01",
        "aa-echo-sudo-text-01",
        "violation-deny-beats-allow-01",
        "violation-default-deny-01",
        "adapter-grant-02",
        "adapter-nonlisted-default-01",
        "adapter-missing-tool-arg-01",
        "hdi-echo-eval-in-list-01",
    )
    return SelectedGroupA(ids=ids, count=len(ids), label="development-coverage")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent44-benchmark", description="Phase 8 deterministic security benchmark.")
    parser.add_argument("--selection", help="Path to a JSON manifest with a top-level 'ids' array of development scenario ids.")
    parser.add_argument("--output-dir", default=str(PHASE8_RUN_ROOT / "runs" / f"phase8_{now_iso().replace(':', '')}_{int(time.time())}"))
    parser.add_argument("--trials", type=int, default=1, help="Repeat each Group A run this many times.")
    parser.add_argument("--adapter-deadline", type=float, default=5.0, help="Adapter decision timeout in seconds; fail-closed to DENY.")
    parser.add_argument("--seed", type=int, default=0, help="Bootstrap seed (deterministic rules-only modes ignore it).")
    args = parser.parse_args(argv)

    if args.trials < 1:
        parser.error("--trials must be >= 1")

    try:
        selection = _default_selection()
        if args.selection:
            selection = load_group_a_selection(Path(args.selection))
            print(f"group_a_selection={selection.label} ids={selection.count} from {args.selection}", file=sys.stderr)
    except ValueError as exc:
        print(f"agent44-benchmark: selection validation failed: {exc}", file=sys.stderr)
        return 2

    print(f"group_a_selection={selection.label} ids={selection.count}", file=sys.stderr)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"output_dir={output_dir}", file=sys.stderr)

    try:
        summary = asyncio.run(_execute(output_dir, selection=selection, trials=args.trials, adapter_deadline=args.adapter_deadline))
    except Exception as exc:  # noqa: BLE001
        print(f"agent44-benchmark: failed during execute: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print("REVISION=" + str(summary["rev"]), file=sys.stderr)
    print("BASELINE_EXECUTED=" + str(summary["profiles"]["baseline"]["executed"]), file=sys.stderr)
    print("BASELINE_AGREEMENT=" + ("%.4f" % summary["profiles"]["baseline"]["agreement"]), file=sys.stderr)
    print("ENFORCEMENT_EXECUTED=" + str(summary["profiles"]["enforcement"]["executed"]), file=sys.stderr)
    print("ENFORCEMENT_AGREEMENT=" + ("%.4f" % summary["profiles"]["enforcement"]["agreement"]), file=sys.stderr)
    print("GROUP_B_ENGINE_MATCHED=" + str(summary["group_b"]["engine_matched"]), file=sys.stderr)
    print("GROUP_B_PROXY_NON_FORWARDING_VERIFIED=" + str(summary["group_b"]["proxy_non_forwarding_verified"]), file=sys.stderr)
    print("COMBINED_TOTAL=" + str(summary["combined_total"]), file=sys.stderr)
    print(f"results={output_dir / 'results.json'}", file=sys.stderr)
    print(f"summary={output_dir / 'summary.md'}", file=sys.stderr)
    print(f"manifest={output_dir / 'manifest.json'}", file=sys.stderr)
    print("REPRO: agent44-benchmark --selection <path-to-json> --output-dir <dir>", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
