"""
config.py  —  Shared runtime settings for the EDR project.

Single source of truth for:
  * the action mode shared by the ThreatAnalyst and the Remediation module
  * the paths + locks of the JSONL files both sides read/write
  * the ledger record helpers used to track which record was handled

This module has no heavy imports on purpose, so any module can import it
without creating circular dependencies.

ACTION MODE
-----------
  "approval"  (default) : nothing destructive runs on its own. Proposed actions
                          are queued in pending_approvals.jsonl and executed
                          only after an operator approves them
                          (python -m src.detection.l4_llm_detection.approval_response_executor).
  "automatic"           : actions are executed immediately.

Override with the environment variable EDR_ACTION_MODE=automatic|approval.
"""
from __future__ import annotations

import hashlib
import os
import threading
import uuid
from typing import Any, Dict, Optional

VALID_ACTION_MODES = ("approval", "automatic")
DEFAULT_ACTION_MODE = "approval"


def normalize_action_mode(mode: Optional[str] = None) -> str:
    """
    Return a valid action mode.

    mode=None  -> use the EDR_ACTION_MODE environment variable, else "approval".
    Unknown values fall back to "approval" (fail closed) with a warning.
    """
    raw = mode if mode is not None else os.environ.get("EDR_ACTION_MODE", DEFAULT_ACTION_MODE)
    value = str(raw).strip().lower()
    if value not in VALID_ACTION_MODES:
        print(
            f"[config][WARN] Unknown action mode {raw!r} - "
            f"falling back to {DEFAULT_ACTION_MODE!r}."
        )
        return DEFAULT_ACTION_MODE
    return value


# Mode shared by the analyst and the remediation module.
ACTION_MODE: str = normalize_action_mode()

# ── Memgraph connection (single source of truth) ─────────────────────────────
# Override with MEMGRAPH_HOST / MEMGRAPH_PORT; defaults match a local Memgraph.
MEMGRAPH_HOST: str = os.environ.get("MEMGRAPH_HOST", "localhost")
MEMGRAPH_PORT: int = int(os.environ.get("MEMGRAPH_PORT", "7687"))

# ── Shared files (relative to the working directory, as before) ──────────────
ACTIONED_NODES_FILE = "actioned_nodes.jsonl"
PENDING_APPROVALS_FILE = "pending_approvals.jsonl"

# Append-only log of approval-queue entries the operator has already executed.
# The approval queue itself is never rewritten (see approval_response_executor):
# a finding is "still pending" iff its analysis_id is in PENDING_APPROVALS_FILE
# and NOT in this file. Appending is safe even while the agent is appending to
# the queue from another process; rewriting the queue was not.
APPROVALS_RESOLVED_FILE = "approvals_resolved.jsonl"

# Serialises every read / rewrite / append of ACTIONED_NODES_FILE. In live mode the
# ThreatAnalyst thread appends to the file while the remediation thread reads it and
# rewrites it (remediation_handled=True): without this lock the rewrite silently
# drops records appended in between.
ACTIONED_NODES_LOCK = threading.RLock()

# Same idea for the approval queue (analyst + remediation both append to it).
PENDING_APPROVALS_LOCK = threading.RLock()


# ── Ledger record identity ───────────────────────────────────────────────────

def new_record_id() -> str:
    """Unique id stamped on every new actioned_nodes.jsonl record."""
    return uuid.uuid4().hex


def ledger_record_key(rec: Dict[str, Any]) -> str:
    """
    Stable identity of one ledger record.

    New records carry "record_id". Older lines written before record_id existed
    get a deterministic hash of their fields, so they keep working.
    """
    rid = rec.get("record_id")
    if rid:
        return str(rid)
    raw = "|".join(
        str(rec.get(k, ""))
        for k in ("guid", "action_type", "target_type", "target_value", "stamped_at", "reason")
    )
    return "legacy:" + hashlib.sha1(raw.encode("utf-8")).hexdigest()
