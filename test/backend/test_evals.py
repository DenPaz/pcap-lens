"""The answer-quality cases (test/evals/cases.json) rest on facts tshark
computes: every case's `facts` must hold for its capture, so a grader that
expects "resets" grades against a capture that has resets."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import triage
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import RequestContext

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
CASES: list[dict[str, Any]] = json.loads((ROOT / "evals" / "cases.json").read_text("utf-8"))[
    "cases"
]
CHECK_IDS = {c.id for c in triage.CHECKS}


def test_cases_name_known_checks() -> None:
    for case in CASES:
        named = set(case.get("facts", {}).get("checks", {})) | set(
            case.get("facts", {}).get("changed", {})
        )
        for item in case.get("expect", []):
            named |= set(item.get("check", []))
        assert named <= CHECK_IDS, (case["id"], named - CHECK_IDS)


def _opened(name: str, ctx: RequestContext) -> PcapService:
    service = PcapService()
    try:
        service.initialize({}, ctx)
        service.open({"path": str(FIXTURES / name), "names": {}}, ctx)
    except BaseException:
        service.shutdown()
        raise
    return service


@pytest.mark.tshark
@pytest.mark.parametrize("case", [c for c in CASES if c["kind"] == "triage"], ids=lambda c: c["id"])
def test_triage_facts(case: dict[str, Any], ctx: RequestContext) -> None:
    service = _opened(case["capture"], ctx)
    try:
        counts = {c["id"]: c.get("count") for c in service.triage({}, ctx)["checks"]}
    finally:
        service.shutdown()
    want = case["facts"]["checks"]
    assert {k: counts[k] for k in want} == want


@pytest.mark.tshark
@pytest.mark.parametrize(
    "case", [c for c in CASES if c["kind"] == "compare"], ids=lambda c: c["id"]
)
def test_compare_facts(case: dict[str, Any], ctx: RequestContext) -> None:
    services: list[PcapService] = []
    try:
        services.extend(_opened(name, ctx) for name in case["captures"])
        before, after = (s.capture_profile({}, ctx) for s in services)
        diff = services[1].compare_profiles({"before": before, "after": after}, ctx)
    finally:
        for s in services:
            s.shutdown()
    changed = {c["id"]: [c["before"], c["after"]] for c in diff["checks"]["changed"]}
    facts = case["facts"]
    assert {k: changed.get(k) for k in facts["changed"]} == facts["changed"]
    assert [e["address"] for e in diff["endpoints"]["new"]] == facts["newEndpoints"]
    assert [e["address"] for e in diff["endpoints"]["gone"]] == facts["goneEndpoints"]
