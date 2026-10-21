
"""Regression tests for agent44.remote_backends (Phase 10)."""

from __future__ import annotations

import pytest

from agent44.policy import Action, Condition, PolicyRule
from agent44.remote_backends import (
    JevAdapter,
    RemoteResponseError,
    ScaleDownClassifyAdapter,
    BackendUnavailableError,
    BackendStatus,
    _parse_noul_probability,
    _parse_scaledown_scores,
)


def _rule(tool: str = "echo") -> PolicyRule:
    return PolicyRule(
        id="r1",
        tool=tool,
        action=Action.ALLOW,
        reason="stub",
        when=Condition(field="x", field_exists=True),
    )


@pytest.mark.parametrize(
    "noul,expected",
    [
        (0.97, Action.ALLOW),
        (0.95, Action.ALLOW),
        (0.5, Action.UNDECIDED),
        (0.1, Action.DENY),
        (0.0, Action.DENY),
    ],
)
async def test_jev_adapter_probability_band(noul, expected):
    async def fake_post(url, headers, body):
        return {
            "model": "jev-latest",
            "answers": {"agent44_policy_check": {"type": "noul", "noul": noul}},
        }

    adapter = JevAdapter(credential="test-token", post=fake_post)
    decision = await adapter.decide("echo", {"x": 1}, [_rule()])
    assert decision.action is expected


async def test_jev_adapter_requires_credential():
    async def fake_post(url, headers, body):
        raise AssertionError("should not be called")

    adapter = JevAdapter(credential=None, post=fake_post)
    with pytest.raises(BackendUnavailableError):
        await adapter.decide("echo", {}, [])
    avail = adapter.availability()
    assert avail.status is BackendStatus.UNAVAILABLE
    assert "no credential" in avail.reason.lower()


async def test_jev_adapter_rejects_invalid_payload():
    async def fake_post(url, headers, body):
        return {"answers": {}}

    adapter = JevAdapter(credential="t", post=fake_post)
    with pytest.raises(RemoteResponseError):
        await adapter.decide("echo", {}, [])


def test_parse_noul_probability_valid_and_invalid():
    payload = {"answers": {"agent44_policy_check": {"type": "noul", "noul": 0.42}}}
    assert _parse_noul_probability(payload, question_name="agent44_policy_check") == 0.42
    assert _parse_noul_probability({}, question_name="agent44_policy_check") is None
    assert _parse_noul_probability(payload, question_name="other") is None

    assert _parse_noul_probability(
        {"answers": {"agent44_policy_check": {"type": "noul", "noul": True}}},
        question_name="agent44_policy_check",
    ) is None
    assert _parse_noul_probability(
        {"answers": {"agent44_policy_check": {"type": "noul", "noul": 1.1}}},
        question_name="agent44_policy_check",
    ) is None


@pytest.mark.parametrize(
    "payload,expected",
    [
        ({"top_label": "allow", "scores": {"allow": 0.92, "deny": 0.08}}, Action.ALLOW),
        ({"top_label": "deny", "scores": {"allow": 0.07, "deny": 0.93}}, Action.DENY),
        ({"top_label": "allow", "scores": {"allow": 1.0, "deny": 0.0}}, Action.ALLOW),
    ],
)
async def test_scaledown_adapter_probability(payload, expected):
    async def fake_post(url, headers, body):
        return payload

    adapter = ScaleDownClassifyAdapter(credential="test-token", post=fake_post)
    decision = await adapter.decide("review_tool", {"note": "x"}, [_rule()])
    assert decision.action is expected


async def test_scaledown_adapter_rejects_invalid_payload():
    async def fake_post(url, headers, body):
        return {"top_label": "allow"}

    adapter = ScaleDownClassifyAdapter(credential="t", post=fake_post)
    with pytest.raises(RemoteResponseError):
        await adapter.decide("review_tool", {}, [])


async def test_scaledown_adapter_requires_credential():
    async def fake_post(url, headers, body):
        raise AssertionError("should not be called")

    adapter = ScaleDownClassifyAdapter(credential=None, post=fake_post)
    with pytest.raises(BackendUnavailableError):
        await adapter.decide("echo", {}, [])


def test_scaledown_build_request_defaults_to_tool_call():
    adapter = ScaleDownClassifyAdapter(credential="t", post=lambda *args, **kwargs: None)
    body = adapter.build_request("echo", {"x": 1})
    assert body["text"] == "tool_call:echo"
    names = {label["name"] for label in body["labels"]}
    assert names == {"allow", "deny"}


def test_scale_down_score_extractors():
    payload = {"top_label": "allow", "scores": {"allow": 0.9, "deny": 0.1}}
    assert _parse_scaledown_scores(payload) == ("allow", 0.9, 0.1)
    assert _parse_scaledown_scores({"top_label": "allow"}) is None
    assert _parse_scaledown_scores({}) is None
