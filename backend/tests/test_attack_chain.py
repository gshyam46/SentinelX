"""
Tests for Phase 2 P2-05 — Attack chain derivation.
Engine tests only — no HTTP, no real DB, no real LLM.
"""
from __future__ import annotations

import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("MOCK_MODE", "true")


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Graph construction helpers
# ---------------------------------------------------------------------------

def _graph(nodes: list[dict], edges: list[dict]) -> dict:
    return {
        "scan_id": "test-scan-001",
        "created_at": "2026-04-29T00:00:00+00:00",
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
    }


def _tool_node(node_id: str, tool_name: str) -> dict:
    return {
        "node_id": node_id,
        "node_type": "tool_execution",
        "tool_name": tool_name,
        "input_params": {"target": "example.com"},
        "output_summary": {"status": "complete", "finding_count": 1},
        "created_at": "2026-04-29T00:00:00+00:00",
    }


def _finding_node(
    node_id: str,
    tool_name: str,
    title: str,
    severity: str,
    cve_id: str | None = None,
    validated: bool | None = None,
) -> dict:
    return {
        "node_id": node_id,
        "node_type": "finding",
        "tool_name": tool_name,
        "finding": {
            "severity": severity,
            "title": title,
            "description": f"Test finding: {title}",
            "cve_id": cve_id,
            "validated": validated,
        },
        "created_at": "2026-04-29T00:00:00+00:00",
    }


def _edge(parent_id: str, child_id: str) -> dict:
    return {"edge_type": "triggered_by", "parent_id": parent_id, "child_id": child_id}


# ---------------------------------------------------------------------------
# test_derive_chains_simple_graph
# tool→finding edge with severity=high → one chain returned, fields correct
# ---------------------------------------------------------------------------

def test_derive_chains_simple_graph():
    from backend.modules.pentest.attack_chain import derive_chains

    graph = _graph(
        nodes=[
            _tool_node("t1", "nmap_scan"),
            _finding_node("f1", "nmap_scan", "Open Port 22 (SSH)", "high"),
        ],
        edges=[_edge("t1", "f1")],
    )

    chains = derive_chains(graph, [])

    assert len(chains) == 1
    chain = chains[0]
    assert chain.entry_point == "nmap_scan"
    assert chain.impact == "Open Port 22 (SSH)"
    assert chain.severity == "high"
    assert len(chain.steps) == 2
    assert chain.steps[0].node_type == "tool"
    assert chain.steps[0].label == "nmap_scan"
    assert chain.steps[1].node_type == "finding"
    assert chain.steps[1].label == "Open Port 22 (SSH)"
    assert chain.steps[1].severity == "high"
    assert chain.kev_in_chain is False
    assert chain.narrative is None
    assert chain.chain_id  # UUID4 string set


# ---------------------------------------------------------------------------
# test_derive_chains_no_edges
# Graph with nodes but zero edges → no paths of length ≥ 2 → returns []
# ---------------------------------------------------------------------------

def test_derive_chains_no_edges():
    from backend.modules.pentest.attack_chain import derive_chains

    graph = _graph(
        nodes=[
            _tool_node("t1", "nmap_scan"),
            _finding_node("f1", "nmap_scan", "Open Port 443", "high"),
        ],
        edges=[],
    )

    chains = derive_chains(graph, [])
    assert chains == []


# ---------------------------------------------------------------------------
# test_derive_chains_low_severity_excluded
# Paths whose highest finding severity is below medium are excluded.
# Covers both info and low.
# ---------------------------------------------------------------------------

def test_derive_chains_low_severity_excluded():
    from backend.modules.pentest.attack_chain import derive_chains

    # info severity — excluded
    info_graph = _graph(
        nodes=[
            _tool_node("t1", "nuclei_scan"),
            _finding_node("f1", "nuclei_scan", "Server Header Disclosure", "info"),
        ],
        edges=[_edge("t1", "f1")],
    )
    assert derive_chains(info_graph, []) == []

    # low severity — excluded
    low_graph = _graph(
        nodes=[
            _tool_node("t2", "nuclei_scan"),
            _finding_node("f2", "nuclei_scan", "Cookie Without HttpOnly Flag", "low"),
        ],
        edges=[_edge("t2", "f2")],
    )
    assert derive_chains(low_graph, []) == []

    # medium severity — included
    medium_graph = _graph(
        nodes=[
            _tool_node("t3", "nuclei_scan"),
            _finding_node("f3", "nuclei_scan", "Directory Listing Enabled", "medium"),
        ],
        edges=[_edge("t3", "f3")],
    )
    chains = derive_chains(medium_graph, [])
    assert len(chains) == 1
    assert chains[0].severity == "medium"


# ---------------------------------------------------------------------------
# test_derive_chains_kev_flagged
# Finding CVE present in kev_matches → kev_in_chain=True
# Finding CVE absent from kev_matches → kev_in_chain=False
# ---------------------------------------------------------------------------

def test_derive_chains_kev_flagged():
    from backend.modules.pentest.attack_chain import derive_chains

    graph = _graph(
        nodes=[
            _tool_node("t1", "nuclei_scan"),
            _finding_node(
                "f1", "nuclei_scan",
                "Log4Shell Remote Code Execution", "critical",
                cve_id="CVE-2021-44228",
            ),
        ],
        edges=[_edge("t1", "f1")],
    )

    # KEV match present
    chains = derive_chains(graph, [], kev_matches=["CVE-2021-44228"])
    assert len(chains) == 1
    assert chains[0].kev_in_chain is True
    assert chains[0].severity == "critical"
    assert chains[0].steps[1].cve == "CVE-2021-44228"

    # No KEV matches passed → kev_in_chain=False
    chains_no_kev = derive_chains(graph, [])
    assert len(chains_no_kev) == 1
    assert chains_no_kev[0].kev_in_chain is False

    # CVE not in kev_matches list → kev_in_chain=False
    chains_other_kev = derive_chains(graph, [], kev_matches=["CVE-2022-99999"])
    assert chains_other_kev[0].kev_in_chain is False


# ---------------------------------------------------------------------------
# test_narrate_chains_mock
# Mock litellm.acompletion returns a string → narrative populated on chain
# ---------------------------------------------------------------------------

def test_narrate_chains_mock():
    from backend.modules.pentest.attack_chain import AttackChain, ChainNode, narrate_chains

    chain = AttackChain(
        chain_id="aaaaaaaa-0000-0000-0000-000000000001",
        entry_point="nmap_scan",
        impact="Open Port 22 (SSH)",
        severity="high",
        steps=[
            ChainNode(node_id="t1", node_type="tool", label="nmap_scan"),
            ChainNode(
                node_id="f1",
                node_type="finding",
                label="Open Port 22 (SSH)",
                severity="high",
            ),
        ],
    )

    mock_choice = MagicMock()
    mock_choice.message.content = (
        "nmap discovered an open SSH port enabling credential brute-force attacks."
    )
    mock_response = MagicMock()
    mock_response.choices = [mock_choice]

    with patch("litellm.acompletion", new=AsyncMock(return_value=mock_response)):
        result = run(narrate_chains([chain]))

    assert len(result) == 1
    assert result[0].narrative == (
        "nmap discovered an open SSH port enabling credential brute-force attacks."
    )
    assert result[0].chain_id == "aaaaaaaa-0000-0000-0000-000000000001"
    assert result[0].severity == "high"


# ---------------------------------------------------------------------------
# test_chain_serializable
# model_dump() must produce a dict that round-trips through JSON without error.
# Validated field cross-referenced from findings list.
# ---------------------------------------------------------------------------

def test_chain_serializable():
    from backend.modules.pentest.attack_chain import derive_chains

    graph = _graph(
        nodes=[
            _tool_node("t1", "zap_scan"),
            _finding_node("f1", "zap_scan", "Reflected XSS on /search", "high", validated=True),
        ],
        edges=[_edge("t1", "f1")],
    )
    validated_findings = [
        {"title": "Reflected XSS on /search", "severity": "high", "validated": True}
    ]

    chains = derive_chains(graph, validated_findings)
    assert len(chains) == 1

    dumped = chains[0].model_dump()
    serialised = json.dumps(dumped)
    restored = json.loads(serialised)

    assert restored["severity"] == "high"
    assert restored["entry_point"] == "zap_scan"
    assert restored["impact"] == "Reflected XSS on /search"
    assert isinstance(restored["steps"], list)
    assert len(restored["steps"]) == 2
    assert restored["steps"][1]["validated"] is True
    assert restored["kev_in_chain"] is False
    assert restored["narrative"] is None
    # chain_id must be a non-empty string (UUID4)
    assert isinstance(restored["chain_id"], str)
    assert len(restored["chain_id"]) == 36


# ---------------------------------------------------------------------------
# test_malformed_graph_returns_empty
# derive_chains must return [] and never raise for any malformed input.
# ---------------------------------------------------------------------------

def test_malformed_graph_returns_empty():
    from backend.modules.pentest.attack_chain import derive_chains

    # Completely empty dict
    assert derive_chains({}, []) == []

    # None graph
    assert derive_chains(None, []) == []  # type: ignore[arg-type]

    # Graph is not a dict (e.g. serialisation error produced a string)
    assert derive_chains("invalid", []) == []  # type: ignore[arg-type]

    # Missing nodes key
    assert derive_chains({"edges": [_edge("t1", "f1")]}, []) == []

    # Missing edges key
    assert derive_chains({"nodes": [_tool_node("t1", "nmap_scan")]}, []) == []

    # Edges reference nodes that do not exist in the nodes list
    dangling = _graph(
        nodes=[_tool_node("t1", "nmap_scan")],
        edges=[_edge("t1", "ghost_node")],
    )
    assert derive_chains(dangling, []) == []

    # nodes list is empty
    assert derive_chains({"nodes": [], "edges": [_edge("t1", "f1")]}, []) == []

    # Nodes with no node_id keys
    broken_nodes = _graph(
        nodes=[{"node_type": "tool_execution", "tool_name": "nmap_scan"}],
        edges=[],
    )
    assert derive_chains(broken_nodes, []) == []
