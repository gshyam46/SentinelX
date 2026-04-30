"""
SentinelX — Pentest Task Tree (PTT)
Phase 2 / ADR-024: state model for adaptive follow-up orchestration.

PTTState is serialised to scan.results["scan_metadata"]["ptt_state"] (JSONB).
No new DB table — stored in the existing results column, safe for old records.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel

logger = logging.getLogger("sentinelx.ptt")


class PTTNodeStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    skipped = "skipped"


class PTTNode(BaseModel):
    node_id: str                                          # uuid4 string
    parent_id: Optional[str]
    node_type: Literal["scan", "hypothesis", "tool_run"]
    label: str                                            # human-readable description
    tool: Optional[str] = None                            # tool name when node_type=tool_run
    status: PTTNodeStatus = PTTNodeStatus.pending
    finding_ids: list[str] = []                           # finding IDs that spawned this node
    suggested_by: Literal["llm", "rule"] = "rule"
    created_at: str                                       # ISO 8601 timestamp


class PTTState(BaseModel):
    scan_id: str
    nodes: list[PTTNode] = []
    edges: list[tuple[str, str]] = []                     # (parent_id, child_id) pairs

    def add_node(self, node: PTTNode) -> None:
        self.nodes.append(node)
        if node.parent_id:
            self.edges.append((node.parent_id, node.node_id))

    def get_pending(self) -> list[PTTNode]:
        return [n for n in self.nodes if n.status == PTTNodeStatus.pending]

    def mark_running(self, node_id: str) -> None:
        for node in self.nodes:
            if node.node_id == node_id:
                node.status = PTTNodeStatus.running
                return
        logger.warning("PTT: mark_running called on unknown node_id=%s", node_id)

    def mark_completed(self, node_id: str) -> None:
        for node in self.nodes:
            if node.node_id == node_id:
                node.status = PTTNodeStatus.completed
                return
        logger.warning("PTT: mark_completed called on unknown node_id=%s", node_id)

    def export(self) -> dict:
        """Return JSON-serialisable dict — safe for JSONB storage."""
        return self.model_dump()
