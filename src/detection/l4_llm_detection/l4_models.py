"""
l4_models.py  —  Shared dataclasses for the L4 analyst layer.

No logic, no imports from other L4 modules → no circular dependencies.
Every other L4 module imports from here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


# ─────────────────────────────────────────────────────────────────────────────
# INVESTIGATION CASE (minimal version)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class InvestigationCase:
    """One unit of work in the investigation engine."""
    case_id:       str
    anchor_guid:   str
    group_guids:   Set[str]      # all GUIDs in this connectivity group
    trigger_score: int           # score of anchor at trigger time
    trigger_time:  str           # ISO timestamp


# ─────────────────────────────────────────────────────────────────────────────
# LLM OUTPUT (from AnalystAgent)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AttackSummary:
    """
    Output of LLM 1. Contains everything needed for response and logging.
    """
    case_id:          str
    anchor_guid:      str
    verdict:          str             # MALICIOUS | SUSPICIOUS only
    severity:         str             # CRITICAL | HIGH | MEDIUM | LOW
    confidence:       str             # HIGH | MEDIUM | LOW
    attack_name:      str
    summary:          str             # 3-sentence max
    confidence_note:  Optional[str]   # missing telemetry or null

    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics:    List[str] = field(default_factory=list)

    # Detailed findings for responder
    attack_chain: List[Dict] = field(default_factory=list)
    processes:    List[Dict] = field(default_factory=list)
    iocs:         List[Dict] = field(default_factory=list)
    files:        List[Dict] = field(default_factory=list)
    identities:   List[str] = field(default_factory=list)
    gaps:         List[Dict] = field(default_factory=list)

    # Audit trail
    raw_llm_response: str = ""