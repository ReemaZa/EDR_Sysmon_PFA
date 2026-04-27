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
import sys 
import json
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from gqlalchemy import Memgraph

from src.detection.l4_llm_detection.analyst_agent import AnalystAgent
from src.detection.l4_llm_detection.graph_extractor import GraphExtractor
from src.detection.l4_llm_detection.investigation_queue import InvestigationQueue
from src.detection.l4_llm_detection.l4_models import AttackSummary, ResponderOutput
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
        threat_threshold:  int = 4,
        max_subgraph_nodes: int = 120,
    ):
        self.query_interval    = query_interval
        self.threat_threshold  = threat_threshold
        self.max_subgraph_nodes = max_subgraph_nodes

        # ── NEW LOGGING SETUP ───────────────────────────────────────────
        self.log_file_path = f"logs/l4_analyst_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        # Open the file in append mode
        self._log_handle = open(self.log_file_path, "a", encoding="utf-8")
        self._log_lock = threading.Lock()
        # ────────────────────────────────────────────────────────────────
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
        self._log(
            f"[ThreatAnalyst] Started — "
            f"interval={self.query_interval}s  "
            f"threshold={self.threat_threshold}"
        )

    def _log(self, message: str):
        """Custom logging method that bypasses the global sys.stdout."""
        timestamp = datetime.utcnow().isoformat()
        formatted_message = f"[{timestamp}] {message}\n"
        
        with self._log_lock:
            # 1. Write to L4-specific file
            self._log_handle.write(formatted_message)
            self._log_handle.flush()
            
            # 2. Write to the ORIGINAL terminal (bypasses agent.py's PrintLogger)
            # This ensures it shows on screen but NOT in the main agent log file.
            sys.__stdout__.write(formatted_message)
            sys.__stdout__.flush()
    # ── SHUTDOWN ──────────────────────────────────────────────────────────────

    def shutdown(self) -> None:
        self._log("Shutting down...")
        self._stop_event.set()
        self._thread.join(timeout=self.query_interval + 5)
        # Close the log handle safely
        with self._log_lock:
            self._log_handle.close()
        self._log("Stopped.")

    # ── BACKGROUND LOOP ───────────────────────────────────────────────────────

    def _loop(self) -> None:
        self._log("[ThreatAnalyst] Background loop started.")
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception as exc:
                import traceback
                self._log(f"[ThreatAnalyst][ERROR] Tick failed: {exc}")
                traceback.print_exc()

            # Sleep in 1-second increments so shutdown() is responsive
            deadline = time.monotonic() + self.query_interval
            while time.monotonic() < deadline and not self._stop_event.is_set():
                time.sleep(1)

    # ── TICK ──────────────────────────────────────────────────────────────────

    def _tick(self) -> None:
        self._stats["ticks"] += 1
        n = self._stats["ticks"]
        self._log(f"\n[ThreatAnalyst] ══ Tick #{n} @ {datetime.utcnow().isoformat()} ══")

        # 1. Scan graph for qualifying nodes
        triggered = self._scan_graph()
        self._log(f"[ThreatAnalyst] {len(triggered)} node(s) above "
                  f"threshold={self.threat_threshold}")

        # 2. Push all triggers to the queue
        for guid, score in triggered:
            self._queue.push(guid, score)
            self._stats["triggers_pushed"] += 1

        # 3. Process batches until no PENDING cases remain
        while True:
            pending = self._queue.pop_all_pending()
            if not pending:
                break

            anchor_item    = pending[0]
            rest           = pending[1:]
            to_investigate = {item.anchor_guid for item in rest}

            self._queue.mark_investigating(anchor_item)
            self._stats["cases_analysed"] += 1

            self._log(f"[ThreatAnalyst] Extracting subgraph  "
                      f"case={anchor_item.case_id[:8]}  "
                      f"anchor={anchor_item.anchor_guid[:20]}  "
                      f"to_investigate={len(to_investigate)}")

            subgraph = self._extractor.extract(
                anchor_guid    = anchor_item.anchor_guid,
                to_investigate = to_investigate,
            )

            if subgraph is None:
                self._log(f"[ThreatAnalyst][WARN] No subgraph returned — concluding empty")
               
             
                for item in rest:
                    self._queue.push(item.anchor_guid, item.trigger_score)
                continue

            self._log(f"[ThreatAnalyst] Running analyst  "
                      f"case={anchor_item.case_id[:8]}  "
                      f"nodes={subgraph.total_nodes}  edges={subgraph.total_edges}")

            finding = self._analyst.analyse(anchor_item, subgraph)
            self._stats["findings"] += 1

            # 4. Conclude anchor
            self._queue.conclude(anchor_item, finding)

            # 5. Conclude absorbed items under the same finding
            for item in rest:
                if item.anchor_guid not in subgraph.unvisited_guids:
                    self._queue.conclude(item, finding)

            self._save_finding(finding)
            self._print_finding(finding)

            # 6. Re-push unvisited items — they become anchors next iteration
            for item in rest:
                if item.anchor_guid in subgraph.unvisited_guids:
                    self._queue.push(item.anchor_guid, item.trigger_score)
            self._log(
            f"[SUBGRAPH GUIDS]\n"
            
            f"  visited   ({len(subgraph.instances)}): "
            f"{[i.guid for i in subgraph.instances]}\n"
            f"  unvisited ({len(subgraph.unvisited_guids)}): "
            f"{list(subgraph.unvisited_guids)}"
        )
        # 7. Age WATCHING cases
        closed = self._queue.tick_watching()
        if closed:
            self._log(f"[ThreatAnalyst] Closed {len(closed)} watched case(s)")

        self._log(f"[ThreatAnalyst] Queue state: {self._queue.get_stats()}")
       
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
            self._log(f"[ThreatAnalyst][SCAN FAIL] {exc}")
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

    def _save_finding(self, finding: ResponderOutput) -> None:
        """Save responder decision to JSONL file.

        Note: This saves the RESPONDER's actions, not the analyst's raw findings.
        The analyst now produces ResponderOutput directly (actions + minimal verdict).
        Heavy attack metadata (techniques, tactics, attack_chain, processes, iocs, files,
        identities, gaps) is NO LONGER stored here because:

        1. LLM now produces actions, not attack narratives
        2. Our prompt explicitly removed techniques/tactics from LLM output
        3. Attack details are ephemeral — only actions and verdict matter for response
        """
        record = {
            "case_id":             finding.case_id,
            "anchor_guid":         finding.anchor_guid,
            "produced_at":         datetime.utcnow().isoformat(),
            "verdict":             finding.verdict,
            "actions":             finding.actions,           # ← new: machine-executable responses
            "analysis_id":         finding.analysis_id,
            "raw_llm_response":    finding.raw_llm_response,  # ← for debugging only
        }
        try:
            with open(FINDINGS_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as exc:
            self._log(f"[ThreatAnalyst][WARN] Could not save responder decision: {exc}")


    def _print_finding(self, finding: ResponderOutput) -> None:
        """Print responder decision to console with formatting."""
        # Severity is gone — verdict alone drives response severity
        verdict_symbol = {
            "MALICIOUS": "🔴", 
            "SUSPICIOUS": "🟠"
        }.get(finding.verdict, "⚪")
    
        self._log(
            f"\n{'=' * 70}\n"
            f"[RESPONDER DECISION]\n"
            f"  Case:       {finding.case_id}\n"
            f"  Anchor:     {finding.anchor_guid}\n"
            f"  Analysis:   {finding.analysis_id}\n"
            f"  Verdict:    {finding.verdict} {verdict_symbol}\n"
            f"  Actions:    {len(finding.actions)} response(s)\n"
        )
    
        # Print actions with full details
        if finding.actions:
            self._log(f"\n  EXECUTABLE ACTIONS:")
            for idx, action in enumerate(finding.actions, 1):
                self._log(
                    f"\n    [{idx}] PRIORITY {action.get('priority', 0)}: {action.get('type')}\n"
                    f"        target: {action.get('target_type')}={action.get('target_value')}\n"
                    f"        scope:  {action.get('scope')}\n"
                    f"        reason: {action.get('reason', 'No reason provided')}"
                )
        else:
            self._log(f"\n  ⚪ NO ACTIONS — monitoring only")
    
        # Show raw LLM response preview for debugging (optional)
        if finding.raw_llm_response and len(finding.raw_llm_response) <= 500:
            self._log(f"\n  RAW LLM (preview): {finding.raw_llm_response[:200]}...")
        elif finding.raw_llm_response:
            self._log(f"\n  RAW LLM: {len(finding.raw_llm_response)} chars (see JSONL)")
    
        self._log(f"{'=' * 70}\n")
    
            # ── STATS ─────────────────────────────────────────────────────────────────
    
    def get_stats(self) -> Dict[str, Any]:
            return {**self._stats, "queue": self._queue.get_stats()}