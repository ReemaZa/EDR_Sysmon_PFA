"""
threat_analyst.py  —  Graph-based threat analyst (L4 detection layer).

RESPONSIBILITY:
    - Start a background daemon thread on construction (no separate start() call needed)
    - Every QUERY_INTERVAL seconds (tick):
        1. Query Memgraph for ProcessInstance nodes with score >= THREAT_THRESHOLD
        2. Push each qualifying node to the InvestigationQueue
        3. Drain all PENDING cases: extract subgraph → run AnalystAgent
        4. Age WATCHING cases (WATCHING → CLOSED after WATCH_HOURS)
        5. Save AnalystFindings to l4_findings.json

DESIGN NOTES:
    - This engine has NO per-event interface. It is not called for each Sysmon
      event. It works purely on the accumulated state of the graph.
    - The pipeline's process_event() does NOT call into this engine at all —
      the engine runs independently on its own timer.
    - shutdown() must be called on program exit (DetectionPipeline.shutdown()
      already does this when enable_l4=True).

CONFIGURATION:
    All parameters are set in the constructor and cannot be changed after start.
    query_interval   : seconds between graph scans          (default 30)
    threat_threshold : minimum ProcessInstance.score        (default 5)
    max_subgraph_nodes: hard cap on nodes sent to analyst   (default 120)
"""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from gqlalchemy import Memgraph

from src.detection.l4_llm_detection.analyst_agent import AnalystAgent
from src.detection.l4_llm_detection.graph_extractor import GraphExtractor
from src.detection.l4_llm_detection.investigation_queue import InvestigationQueue
from src.detection.l4_llm_detection.l4_models import AnalystFinding
from src.graph.Graph_Builder import MEMGRAPH_HOST, MEMGRAPH_PORT

FINDINGS_FILE = "l4_findings.json"


class ThreatAnalyst:
    """
    Graph-based threat analyst — starts automatically on construction.

    Lifecycle:
        analyst = ThreatAnalyst(query_interval=30, threat_threshold=5)
        # background thread is already running
        ...
        analyst.shutdown()   # call on exit
    """

    def __init__(
        self,
        query_interval:    int = 30,
        threat_threshold:  int = 5,
        max_subgraph_nodes: int = 120,
    ):
        self.query_interval    = query_interval
        self.threat_threshold  = threat_threshold
        self.max_subgraph_nodes = max_subgraph_nodes

        # Components
        self._db        = Memgraph(host=MEMGRAPH_HOST, port=MEMGRAPH_PORT)
        self._queue     = InvestigationQueue()
        self._extractor = GraphExtractor(self._db)
        self._analyst   = AnalystAgent()

        # Stats
        self._stats = {
            "ticks":           0,
            "triggers_pushed": 0,
            "cases_analysed":  0,
            "findings":        0,
        }

        # Thread
        self._stop_event = threading.Event()
        self._thread     = threading.Thread(
            target=self._loop,
            name="ThreatAnalyst",
            daemon=True,
        )

        # Start immediately — caller does not need to call start()
        self._thread.start()
        print(
            f"[ThreatAnalyst] Started — "
            f"interval={self.query_interval}s  "
            f"threshold={self.threat_threshold}"
        )

    # ── SHUTDOWN ──────────────────────────────────────────────────────────────

    def shutdown(self) -> None:
        """Signal the background thread to stop and wait for it."""
        print("[ThreatAnalyst] Shutting down...")
        self._stop_event.set()
        self._thread.join(timeout=self.query_interval + 5)
        print("[ThreatAnalyst] Stopped.")

    # ── BACKGROUND LOOP ───────────────────────────────────────────────────────

    def _loop(self) -> None:
        print("[ThreatAnalyst] Background loop started.")
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception as exc:
                import traceback
                print(f"[ThreatAnalyst][ERROR] Tick failed: {exc}")
                traceback.print_exc()

            # Sleep in 1-second increments so shutdown() is responsive
            deadline = time.monotonic() + self.query_interval
            while time.monotonic() < deadline and not self._stop_event.is_set():
                time.sleep(1)

    # ── TICK ──────────────────────────────────────────────────────────────────

    def _tick(self) -> None:
        self._stats["ticks"] += 1
        print(f"\n[ThreatAnalyst] ══ Tick #{self._stats['ticks']} @ {datetime.utcnow().isoformat()} ══")
    
        # 1. Scan graph for all qualifying nodes, already sorted by score desc
        triggered = self._scan_graph()
        print(f"[ThreatAnalyst] {len(triggered)} node(s) above threshold={self.threat_threshold}")
    
        # 2. Push all triggers to queue (deduplication handled inside push())
        for guid, score in triggered:
            self._queue.push(guid, score)
            self._stats["triggers_pushed"] += 1
    
        # 3. Process batches until no PENDING cases remain
        while True:
            pending = self._queue.pop_all_pending()
            if not pending:
                break
            
            anchor_case    = pending[0]
            to_investigate = {case.anchor_guid for case in pending[1:]}
    
            self._queue.mark_investigating(anchor_case)
            self._stats["cases_analysed"] += 1
    
            print(
                f"[ThreatAnalyst] Extracting subgraph  "
                f"anchor={anchor_case.anchor_guid[:20]}  "
                f"to_investigate={len(to_investigate)}"
            )
    
            subgraph = self._extractor.extract(
                anchor_guid    = anchor_case.anchor_guid,
                to_investigate = to_investigate,
            )
    
            if subgraph is None:
                print(f"[ThreatAnalyst][WARN] No subgraph returned for anchor={anchor_case.anchor_guid[:20]}")
                empty = AnalystFinding(
                    case_id               = anchor_case.case_id,
                    anchor_guid           = anchor_case.anchor_guid,
                    severity              = "LOW",
                    confidence            = "LOW",
                    verdict               = "BENIGN",
                    narrative             = "Subgraph extraction returned no data.",
                    mitre_techniques      = [],
                    mitre_tactics         = [],
                    patient_zero_guid     = None,
                    active_guid           = None,
                    false_positive_reason = "No graph data available.",
                    raw_llm_response      = "",
                )
                self._queue.conclude(anchor_case, empty)
                # Re-push the rest so they become anchors next iteration
                for case in pending[1:]:
                    self._queue.push(case.anchor_guid, case.trigger_score)
                continue
            
            # 4. Run analyst on the combined subgraph
            finding = self._analyst.analyse(anchor_case, subgraph)
            self._stats["findings"] += 1
    
            # 5. Conclude anchor case
            self._queue.conclude(anchor_case, finding)
    
            # 6. Conclude all absorbed cases under the same finding
            for case in pending[1:]:
                if case.anchor_guid not in subgraph.unvisited_guids:
                    self._queue.conclude(case, finding)
    
            self._save_finding(finding)
            self._print_finding(finding)
    
            # 7. Re-push not-absorbed cases — they become anchors in next iteration
            for case in pending[1:]:
                if case.anchor_guid in subgraph.unvisited_guids:
                    self._queue.push(case.anchor_guid, case.trigger_score)
    
        # 8. Age WATCHING cases
        closed = self._queue.tick_watching()
        if closed:
            print(f"[ThreatAnalyst] Closed {len(closed)} watched case(s)")
    
        print(f"[ThreatAnalyst] Queue state: {self._queue.get_stats()}")

    # ── GRAPH SCAN ────────────────────────────────────────────────────────────

    def _scan_graph(self) -> List[tuple[str, int]]:
        """
        Find ProcessInstance nodes with score >= threshold.
        Excludes ghosts and nodes already under active investigation.
        Returns list of (guid, score) sorted by score descending.
        """
        try:
            rows = list(self._db.execute_and_fetch(
                """
                MATCH (p:ProcessInstance)
                WHERE p.score >= $threshold
                  AND (p.ghost IS NULL OR p.ghost = false)
                RETURN p.id AS guid, p.score AS score
                ORDER BY p.score DESC
                """,
                {"threshold": self.threat_threshold},
            ))
        except Exception as exc:
            print(f"[ThreatAnalyst][SCAN FAIL] {exc}")
            return []

        # Exclude GUIDs already under active investigation
        active = {
            c.anchor_guid
            for c in self._queue.all_cases()
            if c.status.value in ("INVESTIGATING", "WATCHING")
        }

        return [
            (row["guid"], int(row["score"] or 0))
            for row in rows
            if row.get("guid") and row["guid"] not in active
        ]

    # ── PERSISTENCE ───────────────────────────────────────────────────────────

    def _save_finding(self, finding: AnalystFinding) -> None:
        record = {
            "case_id":             finding.case_id,
            "anchor_guid":         finding.anchor_guid,
            "produced_at":         finding.produced_at,
            "verdict":             finding.verdict,
            "severity":            finding.severity,
            "confidence":          finding.confidence,
            "mitre_techniques":    finding.mitre_techniques,
            "mitre_tactics":       finding.mitre_tactics,
            "patient_zero_guid":   finding.patient_zero_guid,
            "active_guid":         finding.active_guid,
            "narrative":           finding.narrative,
            "false_positive_reason": finding.false_positive_reason,
        }
        try:
            with open(FINDINGS_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as exc:
            print(f"[ThreatAnalyst][WARN] Could not save finding: {exc}")

    def _print_finding(self, finding: AnalystFinding) -> None:
        symbol = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
            finding.severity, "⚪"
        )
        print(
            f"\n{'=' * 70}\n"
            f"[L4 FINDING]\n"
            f"  Case:       {finding.case_id}\n"
            f"  Anchor:     {finding.anchor_guid}\n"
            f"  Verdict:    {finding.verdict}  {symbol} {finding.severity}  "
            f"(confidence: {finding.confidence})\n"
            f"  Techniques: {', '.join(finding.mitre_techniques) or 'none'}\n"
            f"  Tactics:    {', '.join(finding.mitre_tactics)    or 'none'}\n"
            f"  Narrative:  {finding.narrative}\n"
            f"{'=' * 70}\n"
        )

    # ── STATS ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        return {**self._stats, "queue": self._queue.get_stats()}