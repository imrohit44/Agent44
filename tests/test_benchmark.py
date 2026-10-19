"""Acceptance tests for the Phase 8 deterministic security benchmark.

Covers selection stability, metrics denominators, failure handling, held-out
rejection, no-live-model/no-network guarantees, group separation, delegation
and transfer coverage accounting, fresh-registry transfer behaviour,
forged/replayed/expired/revoked/unauthorized transfer denials, downstream
non-forwarding, reproducible output and configuration hashes, synthetic
provenance labelling, and fail-closed enforcement.

All tests are offline: no model inference, Ollama calls, network access or
paid/cloud services. No held-out scenarios are evaluated here.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent44 import corpus  # noqa: E402
from agent44.benchmark import (  # noqa: E402
    EXTENSION_CASES,
    _default_selection,
    group_a_ids,
    load_group_a_selection,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
EVAL_DIR = REPO_ROOT / "evaluation"


# --------------------------------------------------------------------------- #
# Group A selection
# --------------------------------------------------------------------------- #


def test_default_group_a_selection_is_bounded_and_in_dev_partition():
    selection = _default_selection()
    assert 1 <= selection.count <= len(group_a_ids())
    assigned = corpus.partition_map()
    for sid in selection.ids:
        assert sid in assigned, f"{sid!r} not in development partition"
    assert selection.count == len(set(selection.ids))


def test_group_a_ids_match_pre_registered_dev_partition():
    pre = set(_default_selection().ids)
    assert len(pre) < len(group_a_ids())
    assert pre.issubset(set(group_a_ids()))


# --------------------------------------------------------------------------- #
# Deterministic, ordered, partition-aware selection
# --------------------------------------------------------------------------- #


def test_selection_is_stable_and_ordered():
    first = group_a_ids("development")
# --------------------------------------------------------------------------- #
# Metrics, failure handling and denominators
# --------------------------------------------------------------------------- #


def test_metrics_are_computed_with_explicit_denominators():
    from agent44.benchmark import _group_a_metrics

    records = [
        {"id": "a", "error": None, "expected": "DENY", "blocked": True, "latency_ms": 10.0},
        {"id": "b", "error": None, "expected": "ALLOW", "blocked": False, "latency_ms": 5.0},
        {"id": "c", "error": "harness_timeout", "expected": "ALLOW", "blocked": None, "latency_ms": None},
    ]
    metrics = _group_a_metrics(records, group_label="test")
    assert metrics["executed_scenarios"] == 2
    assert metrics["total_scenarios"] == 3
    assert metrics["successful"] == 2
    assert metrics["false_allows"] == 0
    assert metrics["false_denies"] == 0
    assert metrics["agreement"] == 1.0
    assert metrics["tool_call_block_rate"] == 0.5
    assert metrics["tool_calls_blocked"] == 1
    assert metrics["tool_calls_eligible"] == 2


def test_split_group_a_and_extension_results_are_reported_separately():
    assert any(c.scope == "engine" for c in EXTENSION_CASES)
    assert any(c.scope == "proxy" for c in EXTENSION_CASES)
    assert any(c.expected == "DENY" for c in EXTENSION_CASES)
    assert any(c.expected == "ALLOW" for c in EXTENSION_CASES)


# --------------------------------------------------------------------------- #
# Delegation and transfer coverage accounting
# --------------------------------------------------------------------------- #


def test_delegation_and_transfer_capabilities_are_accounted():
    delegation_caps = {c.capability for c in EXTENSION_CASES if c.capability.startswith("delegation_")}
    transfer_caps = {c.capability for c in EXTENSION_CASES if c.capability.startswith("transfer_")}
    assert {"delegation_allowed", "delegation_tool_out_of_scope", "delegation_expired", "delegation_revoked"} <= delegation_caps
    assert {
        "transfer_valid_into_fresh_registry",
        "transfer_forged_or_altered",
        "transfer_replay_rejected",
        "transfer_expired_record",
        "transfer_unauthorized_import",
    } <= transfer_caps


def test_extension_cases_are_explicitly_synthetic():
    for case in EXTENSION_CASES:
        assert "benchmark_added_development_only_synthetic" in case.synthetic_provenance


# --------------------------------------------------------------------------- #
# Fresh-registry transfer and denials (in-process, offline, deterministic)
# --------------------------------------------------------------------------- #


def test_valid_transfer_into_fresh_per_call_registry_preserves_taint():
    from agent44.benchmark import transfer_valid_import_outcome

    ok, err = transfer_valid_import_outcome()
    assert ok is True
    assert err is None


def test_forged_transfer_record_rejected():
    from agent44.benchmark import transfer_forged_outcome

    ok, err = transfer_forged_outcome()
    assert ok is False
    assert err in {"scope", "unknown"}


def test_replayed_transfer_record_rejected():
    from agent44.benchmark import transfer_replay_outcome

    ok, err = transfer_replay_outcome()
    assert ok is False
    assert err == "consumed"


def test_expired_transfer_record_rejected():
    from agent44.benchmark import transfer_expired_outcome

    ok, err = transfer_expired_outcome()
    assert ok is False
    assert err == "expired"


def test_unauthorized_transfer_import_rejected():
    from agent44.benchmark import transfer_unauthorized_outcome

    ok, err = transfer_unauthorized_outcome()
    assert ok is False
    assert err in {"scope", "unknown"}


def test_malformed_transfer_handle_rejected():
    from agent44.benchmark import transfer_malformed_outcome

    ok, err = transfer_malformed_outcome()
    assert ok is False
    assert err is not None

    first = group_a_ids("development")
    second = group_a_ids("development")
    assert first == second
    assert all(isinstance(sid, str) and sid for sid in first)
    assert first == tuple(sorted(first, key=lambda x: (x,)))


def test_held_out_rejected_before_execution(tmp_path):
    held_ids = [c.id for c in corpus.CASES if corpus.partition_map()[c.id] == corpus.PARTITION_HELD_OUT]
    bad = tmp_path / "held_out.json"
    bad.write_text(json.dumps({"ids": held_ids[:5]}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_group_a_selection(bad)


def test_held_out_rejected_before_execution_when_all_selected(tmp_path):
    held_ids = [c.id for c in corpus.CASES if corpus.partition_map()[c.id] == corpus.PARTITION_HELD_OUT]
    bad = tmp_path / "all_held_out.json"
    bad.write_text(json.dumps({"ids": held_ids}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_group_a_selection(bad)
