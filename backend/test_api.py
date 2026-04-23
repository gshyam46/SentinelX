"""Isolated pipeline tests for scan dispatch and orchestration."""

from __future__ import annotations

from datetime import datetime, timezone
import sys
import types
import uuid

import pytest
from fastapi import HTTPException

from backend.api.v1.scans import create_scan
from backend.schemas.scan import ScanRequest
from backend.workers import scan_tasks


class _ScalarResult:
    def __init__(self, value: int) -> None:
        self._value = value

    def scalar(self) -> int:
        return self._value


class _FakeDbSession:
    def __init__(self) -> None:
        self.added: list[object] = []

    async def execute(self, statement) -> _ScalarResult:  # noqa: ANN001
        return _ScalarResult(0)

    def add(self, value: object) -> None:
        self.added.append(value)

    async def commit(self) -> None:
        return None

    async def refresh(self, scan) -> None:  # noqa: ANN001
        if getattr(scan, "id", None) is None:
            scan.id = uuid.uuid4()
        if getattr(scan, "created_at", None) is None:
            scan.created_at = datetime.now(timezone.utc)
        scan.completed_at = getattr(scan, "completed_at", None)
        scan.progress = getattr(scan, "progress", 0) or 0
        scan.current_step = getattr(scan, "current_step", None)


class _FakeFinding:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def to_dict(self) -> dict:
        return dict(self._payload)


class _FakeEvent:
    def __init__(
        self,
        event_type: str,
        *,
        tool: str | None = None,
        finding: _FakeFinding | None = None,
        budget_remaining: int = 0,
        metadata: dict | None = None,
    ) -> None:
        self.type = event_type
        self.tool = tool
        self.finding = finding
        self.budget_remaining = budget_remaining
        self.metadata = metadata

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "tool": self.tool,
            "finding": self.finding.to_dict() if self.finding else None,
            "budget_remaining": self.budget_remaining,
            "metadata": self.metadata or {},
        }


@pytest.mark.asyncio
async def test_create_scan_dispatches_requested_scan_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    delay_calls: list[tuple[str, str, str, str, str]] = []

    monkeypatch.setattr(
        scan_tasks.orchestrate_scan,
        "delay",
        lambda scan_id, domain, tier, scan_type, mode: delay_calls.append(
            (scan_id, domain, tier, scan_type, mode)
        ),
    )

    request = ScanRequest(
        domain="https://www.example.com/",
        scan_type="active",
        scan_mode="deterministic",
        authorization_confirmed=True,
    )
    db = _FakeDbSession()
    current_user = types.SimpleNamespace(
        id=uuid.uuid4(),
        tier="pro",
        scan_count=0,
    )

    response = await create_scan(request, db=db, current_user=current_user)

    assert response.domain == "example.com"
    assert response.scan_type == "active"
    assert delay_calls == [
        (str(response.id), "example.com", "pro", "active", "deterministic")
    ]


@pytest.mark.asyncio
async def test_create_scan_blocks_free_active_requests() -> None:
    request = ScanRequest(
        domain="example.com",
        scan_type="active",
        scan_mode="adaptive",
        authorization_confirmed=True,
    )
    db = _FakeDbSession()
    current_user = types.SimpleNamespace(
        id=uuid.uuid4(),
        tier="free",
        scan_count=0,
    )

    with pytest.raises(HTTPException) as exc_info:
        await create_scan(request, db=db, current_user=current_user)

    assert exc_info.value.status_code == 403


def test_orchestrate_scan_pipeline_runs_requested_mode_end_to_end(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_mode = "deterministic"
    scan_id = str(uuid.uuid4())

    task_updates: list[tuple[str, dict]] = []
    redis_events: list[tuple[str, dict]] = []
    db_events: list[tuple[str, object]] = []
    analyst_calls: list[str] = []
    active_scan_calls: list[dict] = []

    async def fake_run_active_scan(  # noqa: ANN202
        *,
        target: str,
        scan_id: uuid.UUID,
        budget: int,
        allowed_tools: list[str],
        mode: str,
    ):
        active_scan_calls.append(
            {
                "target": target,
                "scan_id": scan_id,
                "budget": budget,
                "allowed_tools": allowed_tools,
                "mode": mode,
            }
        )
        finding = _FakeFinding(
            {
                "title": "Mock finding",
                "severity": "high",
                "description": "Synthetic pipeline finding",
                "target": target,
                "source_tool": "nuclei",
                "owasp_categories": ["A05"],
            }
        )
        yield _FakeEvent("tool_started", tool="nuclei", budget_remaining=3)
        yield _FakeEvent("finding", tool="nuclei", finding=finding, budget_remaining=2)
        yield _FakeEvent(
            "tool_complete",
            tool="nuclei",
            budget_remaining=2,
            metadata={"owasp_coverage": ["A05"]},
        )
        yield _FakeEvent(
            "scan_complete",
            budget_remaining=2,
            metadata={
                "execution_mode": mode,
                "owasp_coverage": ["A05"],
                "tool_timings": [{"tool": "nuclei", "duration_s": 0.01}],
            },
        )

    fake_active_scan_module = types.ModuleType("backend.modules.pentest.active_scan")
    fake_active_scan_module.run_active_scan = fake_run_active_scan
    monkeypatch.setitem(sys.modules, "backend.modules.pentest.active_scan", fake_active_scan_module)

    fake_analyst_module = types.ModuleType("backend.workers.analyst_tasks")
    fake_analyst_module.run_analyst = types.SimpleNamespace(delay=lambda value: analyst_calls.append(value))
    monkeypatch.setitem(sys.modules, "backend.workers.analyst_tasks", fake_analyst_module)

    monkeypatch.setattr(scan_tasks, "_scan_params_for_tier", lambda tier: (3, ["nuclei", "zap"]))
    monkeypatch.setattr(
        scan_tasks.orchestrate_scan,
        "update_state",
        lambda *, state, meta: task_updates.append((state, meta)),
    )
    monkeypatch.setattr(
        scan_tasks,
        "_sync_redis_publish",
        lambda channel, payload: redis_events.append((channel, payload)),
    )

    async def fake_db_set_scan_running(value: uuid.UUID) -> None:
        db_events.append(("running", value))

    async def fake_db_update_tool_started(value: uuid.UUID, tool: str, budget_remaining: int) -> None:
        db_events.append(("tool_started", {"scan_id": value, "tool": tool, "budget_remaining": budget_remaining}))

    async def fake_db_append_finding(value: uuid.UUID, finding_dict: dict) -> None:
        db_events.append(("finding", {"scan_id": value, "finding": finding_dict}))

    async def fake_db_complete_scan(value: uuid.UUID, metadata: dict, tools_run: list[str]) -> None:
        db_events.append(
            (
                "complete",
                {
                    "scan_id": value,
                    "metadata": metadata,
                    "tools_run": tools_run,
                },
            )
        )

    async def fake_db_fail_scan(value: uuid.UUID, error: str) -> None:
        db_events.append(("failed", {"scan_id": value, "error": error}))

    monkeypatch.setattr(scan_tasks, "_db_set_scan_running", fake_db_set_scan_running)
    monkeypatch.setattr(scan_tasks, "_db_update_tool_started", fake_db_update_tool_started)
    monkeypatch.setattr(scan_tasks, "_db_append_finding", fake_db_append_finding)
    monkeypatch.setattr(scan_tasks, "_db_complete_scan", fake_db_complete_scan)
    monkeypatch.setattr(scan_tasks, "_db_fail_scan", fake_db_fail_scan)

    result = scan_tasks.orchestrate_scan.run(
        scan_id,
        "example.com",
        "pro",
        "active",
        requested_mode,
    )

    assert active_scan_calls == [
        {
            "target": "example.com",
            "scan_id": uuid.UUID(scan_id),
            "budget": 3,
            "allowed_tools": ["nuclei", "zap"],
            "mode": requested_mode,
        }
    ]
    assert result == {
        "tools_run": ["nuclei"],
        "findings_count": 1,
        "scan_metadata": {
            "execution_mode": requested_mode,
            "owasp_coverage": ["A05"],
            "tool_timings": [{"tool": "nuclei", "duration_s": 0.01}],
        },
    }
    assert analyst_calls == [scan_id]
    assert ("running", uuid.UUID(scan_id)) in db_events
    assert any(event[0] == "finding" for event in db_events)
    assert any(event[0] == "complete" for event in db_events)
    assert task_updates[-1] == (
        "PROGRESS",
        {
            "step": "Scan complete - queuing analyst",
            "mode": requested_mode,
            "budget_remaining": 2,
            "findings_count": 1,
        },
    )
    assert redis_events[-1] == (
        f"scan:{scan_id}:events",
        {
            "type": "orchestration_complete",
            "scan_id": scan_id,
            "scan_type": "active",
            "mode": requested_mode,
            "findings_count": 1,
            "tools_run": ["nuclei"],
        },
    )
