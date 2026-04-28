"""
investigation_queue.py  —  Case lifecycle manager.

RESPONSIBILITY:
    - Receive trigger events (guid, score) from the analyst engine
    - Deduplicate: one active case per anchor_guid at a time
    - Manage state: PENDING → INVESTIGATING → WATCHING → CLOSED
    - Re-queue WATCHING cases when the graph is updated under them

DEDUPLICATION RULES (enforced in push()):
    No existing / CLOSED      → new PENDING case
    Existing PENDING          → update score if higher, same case
    Existing INVESTIGATING    → mark graph_updated; do NOT create new case
    Existing WATCHING         → re-queue as PENDING, preserve finding as previous_finding

THREAD SAFETY:
    All public methods hold self._lock.
"""
from __future__ import annotations

import threading
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from src.detection.l4_llm_detection.l4_models import (
    AnalystFinding,
    InvestigationCase,
    InvestigationStatus,
)

# Hours a WATCHING case stays before auto-closing
WATCH_HOURS = 2


class InvestigationQueue:

    def __init__(self):
        self._lock  = threading.Lock()
        self._cases: Dict[str, InvestigationCase] = {}   # anchor_guid → case

    # ── TRIGGER ──────────────────────────────────────────────────────────────

    def push(self, guid: str, score: int) -> InvestigationCase:
        """Register or update a trigger for guid."""
        with self._lock:
            now      = datetime.utcnow().isoformat()
            existing = self._cases.get(guid)

            # No case or previous one was fully closed → fresh start
            if existing is None or existing.status == InvestigationStatus.CLOSED:
                case = InvestigationCase(
                    case_id       = str(uuid.uuid4()),
                    anchor_guid   = guid,
                    trigger_score = score,
                    trigger_time  = now,
                )
                self._cases[guid] = case
                print(f"[Queue] NEW     case={case.case_id[:8]}  guid={guid[:20]}  score={score}")
                return case

            # Already queued — just bump score if higher
            if existing.status == InvestigationStatus.PENDING:
                if score > existing.trigger_score:
                    existing.trigger_score = score
                print(f"[Queue] UPDATE  case={existing.case_id[:8]}  score={score}")
                return existing

            # Analyst is running — flag the update, do not spawn a new case
            if existing.status == InvestigationStatus.INVESTIGATING:
                existing.graph_updated = True
                existing.update_count += 1
                print(f"[Queue] UPDATED case={existing.case_id[:8]}  "
                      f"(update #{existing.update_count} during analysis)")
                return existing

            # WATCHING → re-investigate with continuity
            old_finding = existing.finding
            case = InvestigationCase(
                case_id          = str(uuid.uuid4()),
                anchor_guid      = guid,
                trigger_score    = score,
                trigger_time     = now,
                previous_finding = old_finding,
            )
            self._cases[guid] = case
            print(f"[Queue] RE-QUEUE case={case.case_id[:8]}  guid={guid[:20]}  "
                  f"(was {existing.status.value})")
            return case

    # ── ANALYST INTERFACE ─────────────────────────────────────────────────────
    def pop_all_pending(self) -> List[InvestigationCase]:
        """
        Return ALL PENDING cases sorted by score descending.
        Does NOT change their status — caller must call mark_investigating()
        on the anchor case separately.
        """
        with self._lock:
            pending = [
                c for c in self._cases.values()
                if c.status == InvestigationStatus.PENDING
            ]
            return sorted(pending, key=lambda c: -c.trigger_score)
    def pop_next(self) -> Optional[InvestigationCase]:
        """Return the highest-score PENDING case, or None."""
        with self._lock:
            pending = [c for c in self._cases.values()
                       if c.status == InvestigationStatus.PENDING]
            return max(pending, key=lambda c: c.trigger_score) if pending else None

    def mark_investigating(self, case: InvestigationCase) -> None:
        with self._lock:
            case.status        = InvestigationStatus.INVESTIGATING
            case.graph_updated = False
            print(f"[Queue] INVESTIGATING  case={case.case_id[:8]}")

    def conclude(self, case: InvestigationCase, finding: AnalystFinding) -> None:
        """
        Store finding. If graph was updated during analysis, re-queue immediately
        so the analyst re-runs with fresh data.
        """
        with self._lock:
            case.finding = finding

            if case.graph_updated:
                print(f"[Queue] RE-QUEUE (graph changed during analysis)  "
                      f"case={case.case_id[:8]}")
                case.previous_finding = finding
                case.finding          = None
                case.status           = InvestigationStatus.PENDING
                case.graph_updated    = False
                case.update_count     = 0
            else:
                case.status         = InvestigationStatus.WATCHING
                case.watching_since = datetime.utcnow().isoformat()
                print(f"[Queue] WATCHING  case={case.case_id[:8]}  "
                      f"verdict={finding.verdict}  ")

    def tick_watching(self) -> List[InvestigationCase]:
        """Transition WATCHING cases older than WATCH_HOURS to CLOSED."""
        closed = []
        cutoff = datetime.utcnow() - timedelta(hours=WATCH_HOURS)
        with self._lock:
            for case in list(self._cases.values()):
                if case.status != InvestigationStatus.WATCHING:
                    continue
                if not case.watching_since:
                    continue
                if datetime.fromisoformat(case.watching_since) < cutoff:
                    case.status = InvestigationStatus.CLOSED
                    closed.append(case)
                    print(f"[Queue] CLOSED  case={case.case_id[:8]}")
        return closed

    # ── INSPECTION ────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            counts: Dict[str, int] = {s.value: 0 for s in InvestigationStatus}
            for c in self._cases.values():
                counts[c.status.value] += 1
            return counts

    def all_cases(self) -> List[InvestigationCase]:
        with self._lock:
            return list(self._cases.values())