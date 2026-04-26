"""
l4_models.py  —  Shared dataclasses for the L4 analyst layer.

No logic, no imports from other L4 modules → no circular dependencies.
Every other L4 module imports from here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# INVESTIGATION STATE MACHINE
# ─────────────────────────────────────────────────────────────────────────────

class InvestigationStatus(Enum):
    PENDING       = "PENDING"        # queued, not yet picked up
    INVESTIGATING = "INVESTIGATING"  # analyst is running
    WATCHING      = "WATCHING"       # concluded, monitoring for re-trigger
    CLOSED        = "CLOSED"         # no new activity for WATCH_HOURS


# ─────────────────────────────────────────────────────────────────────────────
# SUBGRAPH CONTEXT  (GraphExtractor → AnalystAgent)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class InstanceNode:
    """ProcessInstance with its template fields resolved."""
    guid:         str
    score:        int
    ghost:        bool
    alive:        bool
    start_time:   Optional[str]
    end_time:     Optional[str]
    image:        Optional[str]
    parent_image: Optional[str]
    cmdline:      Optional[str]
    user:         Optional[str]
    description:  Optional[str]


@dataclass
class ArtifactNode:
    """Non-process node: File | Network | Registry | DNS | Driver."""
    id:    str
    label: str
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BehaviourEdge:
    """Scored behaviour edge between two graph nodes."""
    src_id:      str
    dst_id:      str
    rel_type:    str
    total_score: int
    count:       int
    first_seen:  str
    last_seen:   str
    techniques:  List[str]
    tactics:     List[str]
    finding_ids: List[str]
    extra:       Dict[str, Any] = field(default_factory=dict)


@dataclass
class SubgraphContext:
    """
    Complete context package for one investigation case.
    Built by GraphExtractor, consumed by AnalystAgent.
    """
    anchor_guid:       str
    anchor_score:      int
    instances:         List[InstanceNode]   = field(default_factory=list)
    artifacts:         List[ArtifactNode]   = field(default_factory=list)
    edges:             List[BehaviourEdge]  = field(default_factory=list)
    timeline:          List[Dict[str, str]] = field(default_factory=list)
    has_ghost_parents: bool = False
    total_nodes:       int  = 0
    total_edges:       int  = 0


# ─────────────────────────────────────────────────────────────────────────────
# ANALYST FINDING  (output of AnalystAgent)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AnalystFinding:
    """Structured output from the Analyst agent."""
    case_id:               str
    anchor_guid:           str
    severity:              str   # CRITICAL | HIGH | MEDIUM | LOW
    confidence:            str   # HIGH | MEDIUM | LOW
    verdict:               str   # MALICIOUS | SUSPICIOUS | BENIGN
    narrative:             str
    mitre_techniques:      List[str]
    mitre_tactics:         List[str]
    patient_zero_guid:     Optional[str]
    active_guid:           Optional[str]
    false_positive_reason: Optional[str]
    raw_llm_response:      str
    produced_at:           str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )


# ─────────────────────────────────────────────────────────────────────────────
# INVESTIGATION CASE
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class InvestigationCase:
    """One unit of work in the investigation queue."""
    case_id:          str
    anchor_guid:      str
    trigger_score:    int
    trigger_time:     str
    status:           InvestigationStatus = InvestigationStatus.PENDING

    graph_updated:    bool = False   # set by push() while INVESTIGATING
    update_count:     int  = 0

    finding:          Optional[AnalystFinding] = None
    watching_since:   Optional[str]            = None
    previous_finding: Optional[AnalystFinding] = None