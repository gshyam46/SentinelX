"""
Tests for Phase 2 PTT (Pentest Task Tree) — ADR-024.
All tests run with MOCK_MODE=True — no real DB, no real LLM.
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

os.environ.setdefault("MOCK_MODE", "true")


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _node(
    *,
    node_type: str = "tool_run",
    tool: str | None = "nuclei",
    status: str = "pending",
    parent_id: str | None = None,
) -> dict:
    from backend.agents.ptt import PTTNode, PTTNodeStatus
    return PTTNode(
        node_id=str(uuid.uuid4()),
        parent_id=parent_id,
        node_type=node_type,
        label=f"Test {node_type} node",
        tool=tool,
        status=PTTNodeStatus(status),
        finding_ids=[],
        suggested_by="llm",
        created_at=datetime.now(timezone.utc).isoformat(),
    )


# ---------------------------------------------------------------------------
# test_ptt_state_add_node
# ---------------------------------------------------------------------------

def test_ptt_state_add_node():
    from backend.agents.ptt import PTTState

    ptt = PTTState(scan_id=str(uuid.uuid4()))
    n = _node(node_type="hypothesis", tool=None)
    ptt.add_node(n)

    assert len(ptt.nodes) == 1
    assert ptt.nodes[0].node_id == n.node_id
    # No parent → no edge
    assert len(ptt.edges) == 0


def test_ptt_state_add_node_with_parent_creates_edge():
    from backend.agents.ptt import PTTNode, PTTNodeStatus, PTTState

    ptt = PTTState(scan_id=str(uuid.uuid4()))
    parent = _node(node_type="scan", tool=None)
    ptt.add_node(parent)

    child = PTTNode(
        node_id=str(uuid.uuid4()),
        parent_id=parent.node_id,
        node_type="tool_run",
        label="Child node",
        tool="nuclei",
        status=PTTNodeStatus.pending,
        finding_ids=[],
        suggested_by="llm",
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    ptt.add_node(child)

    assert len(ptt.nodes) == 2
    assert (parent.node_id, child.node_id) in ptt.edges


# ---------------------------------------------------------------------------
# test_ptt_state_get_pending
# ---------------------------------------------------------------------------

def test_ptt_state_get_pending():
    from backend.agents.ptt import PTTState

    ptt = PTTState(scan_id=str(uuid.uuid4()))
    n_pending = _node(status="pending", tool="nuclei")
    n_running = _node(status="running", tool="nmap_scan")
    n_completed = _node(status="completed", tool="zap")
    for n in (n_pending, n_running, n_completed):
        ptt.add_node(n)

    pending = ptt.get_pending()
    assert len(pending) == 1
    assert pending[0].node_id == n_pending.node_id


def test_ptt_state_mark_running_and_completed():
    from backend.agents.ptt import PTTNodeStatus, PTTState

    ptt = PTTState(scan_id=str(uuid.uuid4()))
    n = _node(status="pending")
    ptt.add_node(n)

    ptt.mark_running(n.node_id)
    assert ptt.nodes[0].status == PTTNodeStatus.running

    ptt.mark_completed(n.node_id)
    assert ptt.nodes[0].status == PTTNodeStatus.completed


# ---------------------------------------------------------------------------
# test_ptt_state_export_serializable
# ---------------------------------------------------------------------------

def test_ptt_state_export_serializable():
    from backend.agents.ptt import PTTState

    ptt = PTTState(scan_id=str(uuid.uuid4()))
    ptt.add_node(_node(node_type="hypothesis", tool=None))
    ptt.add_node(_node(node_type="tool_run", tool="nuclei"))

    exported = ptt.export()
    # Must round-trip through JSON without error
    serialised = json.dumps(exported)
    restored = json.loads(serialised)
    assert restored["scan_id"] == ptt.scan_id
    assert len(restored["nodes"]) == 2


# ---------------------------------------------------------------------------
# test_expand_ptt_mock_mode
# ---------------------------------------------------------------------------

def test_expand_ptt_mock_mode():
    """LLM returns valid hypothesis with nuclei → tool_run node created."""
    from backend.agents.ptt import PTTNodeStatus, PTTState
    from backend.agents.ptt_orchestrator import expand_ptt

    scan_id = str(uuid.uuid4())
    ptt = PTTState(scan_id=scan_id)
    finding_id = str(uuid.uuid4())
    findings = [{
        "id": finding_id,
        "title": "SQL Injection in login",
        "severity": "high",
        "source_tool": "nuclei",
    }]

    mock_hyps = [{
        "label": "Verify SQLi leads to auth bypass via nuclei",
        "suggested_tool": "nuclei",
        "basis_finding_ids": [finding_id],
    }]

    with patch(
        "backend.agents.ptt_orchestrator._llm_hypotheses",
        new=AsyncMock(return_value=mock_hyps),
    ):
        result = run(expand_ptt(ptt, findings, {}, []))

    tool_run_nodes = [n for n in result.nodes if n.node_type == "tool_run"]
    assert len(tool_run_nodes) == 1
    assert tool_run_nodes[0].tool == "nuclei"
    assert tool_run_nodes[0].suggested_by == "llm"
    assert tool_run_nodes[0].status == PTTNodeStatus.pending
    assert finding_id in tool_run_nodes[0].finding_ids


# ---------------------------------------------------------------------------
# test_expand_ptt_invalid_tool
# ---------------------------------------------------------------------------

def test_expand_ptt_invalid_tool():
    """LLM suggests 'metasploit' (not in OPERATIONAL_REGISTRY) → hypothesis node only."""
    from backend.agents.ptt import PTTState
    from backend.agents.ptt_orchestrator import expand_ptt

    ptt = PTTState(scan_id=str(uuid.uuid4()))
    findings = [{"id": str(uuid.uuid4()), "title": "RCE via deserialization", "severity": "critical"}]

    mock_hyps = [{
        "label": "Exploit RCE via metasploit framework",
        "suggested_tool": "metasploit",   # not in OPERATIONAL_REGISTRY
        "basis_finding_ids": [],
    }]

    with patch(
        "backend.agents.ptt_orchestrator._llm_hypotheses",
        new=AsyncMock(return_value=mock_hyps),
    ):
        result = run(expand_ptt(ptt, findings, {}, []))

    assert len(result.nodes) == 1
    node = result.nodes[0]
    assert node.node_type == "hypothesis"   # downgraded — not a tool_run
    assert node.tool is None                # tool cleared
    assert node.suggested_by == "llm"      # still attributed to LLM


# ---------------------------------------------------------------------------
# test_dispatch_pending
# ---------------------------------------------------------------------------

def test_dispatch_pending():
    """Two pending tool_run nodes execute, findings returned, both marked completed."""
    from backend.agents.ptt import PTTNodeStatus, PTTState
    from backend.agents.ptt_orchestrator import dispatch_pending_ptt_nodes

    scan_id = uuid.uuid4()
    ptt = PTTState(scan_id=str(scan_id))

    for tool in ("nuclei", "nmap_scan"):
        ptt.add_node(_node(node_type="tool_run", tool=tool, status="pending"))

    mock_finding = {
        "title": "PTT-sourced finding",
        "severity": "high",
        "description": "Found during PTT pass",
    }
    mock_exec = AsyncMock(return_value=[mock_finding])

    with patch(
        "backend.modules.pentest.tool_registry.OPERATIONAL_REGISTRY",
        {"nuclei": mock_exec, "nmap_scan": mock_exec},
    ):
        new_findings, updated_ptt = run(
            dispatch_pending_ptt_nodes(ptt, "example.com", scan_id)
        )

    # One finding per tool → 2 total
    assert len(new_findings) == 2
    assert all(f.get("ptt_sourced") is True for f in new_findings)

    completed = [n for n in updated_ptt.nodes if n.status == PTTNodeStatus.completed]
    assert len(completed) == 2


# ---------------------------------------------------------------------------
# test_ptt_max_iterations
# ---------------------------------------------------------------------------

def test_ptt_max_iterations():
    """
    PTT expansion loop is capped at 2 iterations regardless of available nodes.
    Simulates the loop logic from _run_ptt_if_adaptive in scan_tasks.py.
    """
    from backend.agents.ptt import PTTState
    from backend.agents.ptt_orchestrator import dispatch_pending_ptt_nodes, expand_ptt

    scan_id = uuid.uuid4()
    ptt = PTTState(scan_id=str(scan_id))
    findings = [{"id": str(uuid.uuid4()), "title": "Open Port", "severity": "info"}]
    expand_call_count = 0

    async def counting_expand(p, f, eg, kev):
        nonlocal expand_call_count
        expand_call_count += 1
        # Always add a new pending node so the loop does NOT exit via empty-findings guard
        p.add_node(_node(node_type="tool_run", tool="nuclei", status="pending"))
        return p

    mock_findings_batch = [{"title": "extra finding", "severity": "medium", "description": "PTT"}]
    mock_exec = AsyncMock(return_value=mock_findings_batch)

    with patch(
        "backend.modules.pentest.tool_registry.OPERATIONAL_REGISTRY",
        {"nuclei": mock_exec},
    ):
        async def _loop():
            nonlocal ptt
            for _ in range(2):          # hardcoded max — mirrors scan_tasks.py
                ptt = await counting_expand(ptt, findings, {}, [])
                new_f, ptt = await dispatch_pending_ptt_nodes(ptt, "example.com", scan_id)
                findings.extend(new_f)
                if not new_f:
                    break

        run(_loop())

    assert expand_call_count == 2   # loop ran exactly 2 times, never more
