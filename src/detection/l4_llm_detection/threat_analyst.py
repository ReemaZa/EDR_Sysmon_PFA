"""
threat_analyst.py  —  Graph-based threat analyst (L4 detection layer).

RESPONSIBILITY:
    - Start a background daemon thread on construction
    - Every query_interval seconds (tick):
        1. Query Memgraph for ProcessInstance nodes with:
               score >= threshold
           AND (last_analysed_score IS NULL OR score > last_analysed_score)
        2. Extract one subgraph covering all qualifying nodes
        3. Split the subgraph into connected components
        4. For each component run one sequential LLM call
        5. Write verdict + last_analysed_score back to every node
           in the component
        6. Save findings to l4_findings.json

DESIGN:
    - No investigation queue, no state machine.
    - "Should this be re-analysed?" is answered entirely by comparing
      p.score vs p.last_analysed_score on the node itself.
    - Sequential LLM calls per component (no concurrency for now).
    - shutdown() must be called on program exit.
"""
from __future__ import annotations

import json
import sys
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from gqlalchemy import Memgraph

from src.detection.l4_llm_detection.analyst_agent import AnalystAgent
from src.detection.l4_llm_detection.graph_extractor import (
    GraphExtractor,
    SubgraphContext,
    InstanceNode,
    ArtifactNode,
    BehaviourEdge,
)
from src.detection.l4_llm_detection.l4_models import ResponderOutput
from src.graph.Graph_Builder import MEMGRAPH_HOST, MEMGRAPH_PORT

FINDINGS_FILE = "l4_findings.json"


class ThreatAnalyst:
    """
    Graph-based threat analyst — starts automatically on construction.

    Lifecycle:
        analyst = ThreatAnalyst(query_interval=30, threat_threshold=4)
        # background thread is already running
        ...
        analyst.shutdown()
    """

    def __init__(
        self,
        query_interval:     int = 30,
        threat_threshold:   int = 4,
        max_subgraph_nodes: int = 120,
    ):
        self.query_interval     = query_interval
        self.threat_threshold   = threat_threshold
        self.max_subgraph_nodes = max_subgraph_nodes

        # Logging
        import os
        os.makedirs("logs", exist_ok=True)
        self.log_file_path = f"logs/l4_analyst_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self._log_handle   = open(self.log_file_path, "a", encoding="utf-8")
        self._log_lock     = threading.Lock()

        # Components
        self._db        = Memgraph(host=MEMGRAPH_HOST, port=MEMGRAPH_PORT)
        self._extractor = GraphExtractor(self._db)
        self._analyst   = AnalystAgent()

        # Stats
        self._stats = {
            "ticks":          0,
            "components_analysed": 0,
            "findings":       0,
        }

        # Thread
        self._stop_event = threading.Event()
        self._thread     = threading.Thread(
            target=self._loop,
            name="ThreatAnalyst",
            daemon=True,
        )
        self._thread.start()
        self._log(
            f"[ThreatAnalyst] Started — "
            f"interval={self.query_interval}s  "
            f"threshold={self.threat_threshold}"
        )

    # ── LOGGING ───────────────────────────────────────────────────────────────

    def _log(self, message: str):
        timestamp = datetime.utcnow().isoformat()
        formatted = f"[{timestamp}] {message}\n"
        with self._log_lock:
            self._log_handle.write(formatted)
            self._log_handle.flush()
            sys.__stdout__.write(formatted)
            sys.__stdout__.flush()

    # ── SHUTDOWN ──────────────────────────────────────────────────────────────

    def shutdown(self) -> None:
        self._log("[ThreatAnalyst] Shutting down...")
        self._stop_event.set()
        self._thread.join(timeout=self.query_interval + 5)
        with self._log_lock:
            self._log_handle.close()

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
    
        candidates = self._scan_graph()
        self._log(f"[ThreatAnalyst] {len(candidates)} candidate(s) above threshold={self.threat_threshold}")
        if not candidates:
            return
    
        # Remaining pool — shrinks as nodes get visited
        remaining = [guid for guid, _ in candidates]
    
        while remaining:
            anchor_guid    = remaining[0]
            to_investigate = set(remaining[1:])
    
            self._log(f"[ThreatAnalyst] Extracting subgraph  anchor={anchor_guid[:20]}  to_investigate={len(to_investigate)}")
    
            subgraph = self._extractor.extract(
                anchor_guid    = anchor_guid,
                to_investigate = to_investigate,
            )
    
            if subgraph is None:
                self._log(f"[ThreatAnalyst][WARN] No subgraph for {anchor_guid} — skipping")
                remaining.pop(0)
                continue
            
            self._log(f"[ThreatAnalyst] Running analyst  nodes={subgraph.total_nodes}  edges={subgraph.total_edges}")
    
            finding = self._analyst.analyse(subgraph)
            self._stats["findings"] += 1
            investigated_guids=remaining
            self._apply_verdict(subgraph, finding,investigated_guids)
            
            self._apply_graph_actions(finding)
            self._save_finding(finding)
            self._print_finding(finding)
    
            self._log(
                f"[SUBGRAPH GUIDS]\n"
                f"  visited   ({len(subgraph.instances)}): {[i.guid for i in subgraph.instances]}\n"
                f"  unvisited ({len(subgraph.unvisited_guids)}): {list(subgraph.unvisited_guids)}"
            )
    
            # Remove visited from remaining, keep unvisited for next iteration
            visited = {i.guid for i in subgraph.instances}
            remaining = [g for g in remaining if g not in visited]
            # unvisited_guids stay in remaining naturally since they weren't visited
            # ── NEW: execute containment actions in a parallel thread ──
            #if finding.verdict in ("MALICIOUS", "SUSPICIOUS") and finding.actions:
            #    self._executor.execute_async(finding.actions, finding.anchor_guid)

    # ── GRAPH SCAN ────────────────────────────────────────────────────────────

    def _scan_graph(self) -> List[Tuple[str, int]]:
        """
        Find ProcessInstance nodes that:
          - have score >= threshold
          - are not ghosts
          - have a score that changed since the last LLM analysis
            (last_analysed_score IS NULL  OR  score > last_analysed_score)

        Returns list of (guid, score) sorted by score descending.
        """
        try:
            rows = list(self._db.execute_and_fetch(
                """
                MATCH (p:ProcessInstance)
                WHERE p.score >= $threshold
                  
                  AND (
                    p.last_analysed_score IS NULL
                    OR p.score > p.last_analysed_score
                  )
                RETURN p.id AS guid, p.score AS score
                ORDER BY p.score DESC
                """,
                {"threshold": self.threat_threshold},
            ))
        except Exception as exc:
            self._log(f"[ThreatAnalyst][SCAN FAIL] {exc}")
            return []

        return [
            (row["guid"], int(row["score"] or 0))
            for row in rows
            if row.get("guid")
        ]



    # ── APPLY VERDICT ─────────────────────────────────────────────────────────
# ── APPLY VERDICT ─────────────────────────────────────────────────────────────

    def _apply_verdict(
        self,
        component: SubgraphContext,
        result: ResponderOutput,
        investigated_guids: Set[str],
    ) -> None:
        """
        Write last_analysed_score, last_verdict, last_analysed_at
        ONLY onto ProcessInstance nodes that were in the original
        investigated set (i.e. triggered this analysis cycle).
        Context-only nodes pulled in for graph structure are NOT updated.
        """
        ts = datetime.utcnow().isoformat()
        for inst in component.instances:
            if inst.guid not in investigated_guids:
                self._log(
                    f"[ThreatAnalyst] Skipping verdict stamp for context-only node {inst.guid[:20]}"
                )
                continue
            try:
                self._db.execute(
                    """
                    MATCH (p:ProcessInstance {id: $guid})
                    SET p.last_analysed_score = p.score,
                       
                        p.last_analysed_at    = $ts
                    """,
                    {"guid": inst.guid, "verdict": result.verdict, "ts": ts},
                )
            except Exception as exc:
                self._log(
                    f"[ThreatAnalyst][WARN] Could not apply verdict to {inst.guid}: {exc}"
                )

    # ── APPLY GRAPH ACTIONS ───────────────────────────────────────────────────────

    def _apply_graph_actions(self, result: ResponderOutput) -> None:
        """
        Write action tags back to their target nodes in the graph.
    
        Mapping:
            target_type=guid       → ProcessInstance  → tag + action_type label
            target_type=file       → File artifact    → tag
            target_type=ip         → Network artifact → tag
            target_type=domain     → DNS artifact     → tag
            target_type=registry   → Registry artifact→ tag
    
        Each action stamps:
            pending_action   = action["type"]   (e.g. "process_termination")
            action_priority  = action["priority"]
            action_reason    = action["reason"]
            action_stamped_at = <utcnow>
        """
        if not result.actions:
            return
    
        ts = datetime.utcnow().isoformat()
    
        for action in result.actions:
            target_type  = action.get("target_type", "")
            target_value = action.get("target_value", "")
            action_type  = action.get("type", "unknown")
            priority     = action.get("priority", 0)
            reason       = action.get("reason", "")
    
            if not target_value:
                continue
            
            try:
                if target_type == "guid":
                    # ProcessInstance node — stamp pending_action directly
                    self._db.execute(
                        """
                        MATCH (p:ProcessInstance {id: $val})
                        SET p.pending_action    = $action_type,
                            p.action_reason     = $reason,
                            p.action_stamped_at = $ts
                        """,
                        {
                            "val":         target_value,
                            "action_type": action_type,
                            "reason":      reason,
                            "ts":          ts,
                        },
                    )
                    self._log(
                        f"[ThreatAnalyst][ACTION] [{action_type}] → ProcessInstance {target_value[:20]}"
                    )
    
                elif target_type == "file":
                    # File artifact — match by id (which is the path in your schema)
                    #Todo: standarize fileName
                    self._db.execute(
                        """
                        MATCH (f:File {id: $val})
                        SET f.pending_action    = $action_type,
                            f.action_reason     = $reason,
                            f.action_stamped_at = $ts
                        """,
                        {
                            "val":         target_value,
                            "action_type": action_type,
                            "priority":    priority,
                            "reason":      reason,
                            "ts":          ts,
                        },
                    )
                elif target_type == "user":
                    self._db.execute(
                        """
                        MATCH (u:User {id: $val})
                        SET u.pending_action    = $action_type,
                            u.action_reason     = $reason,
                            u.action_stamped_at = $ts
                        """,
                        {"val": target_value, "action_type": action_type,
                         "priority": priority, "reason": reason, "ts": ts},
                    )
                    self._log(
                        f"[ThreatAnalyst][ACTION] [{action_type}] → User {target_value}"
                    )
    
                elif target_type == "ip":
                    self._db.execute(
                        """
                        MATCH (n:Network {id: $val})
                        SET n.pending_action    = $action_type,
                            n.action_reason     = $reason,
                            n.action_stamped_at = $ts
                        """,
                        {
                            "val":         target_value,
                            "action_type": action_type,
                            "priority":    priority,
                            "reason":      reason,
                            "ts":          ts,
                        },
                    )
                    self._log(
                        f"[ThreatAnalyst][ACTION] [{action_type}] → Network {target_value}"
                    )
    
                elif target_type == "domain":
                    self._db.execute(
                        """
                        MATCH (d:DNS {id: $val})
                        SET d.pending_action    = $action_type,
                            d.action_reason     = $reason,
                            d.action_stamped_at = $ts
                        """,
                        {
                            "val":         target_value,
                            "action_type": action_type,
                        
                            "reason":      reason,
                            "ts":          ts,
                        },
                    )
                    self._log(
                        f"[ThreatAnalyst][ACTION] [{action_type}] → DNS {target_value}"
                    )
    
                elif target_type == "registry":
                    self._db.execute(
                        """
                        MATCH (r:Registry {id: $val})
                        SET r.pending_action    = $action_type,
                            r.action_reason     = $reason,
                            r.action_stamped_at = $ts
                        """,
                        {
                            "val":         target_value,
                            "action_type": action_type,
                            "priority":    priority,
                            "reason":      reason,
                            "ts":          ts,
                        },
                    )
                    self._log(
                        f"[ThreatAnalyst][ACTION] [{action_type}] → Registry {target_value}"
                    )
                
                else:
                    self._log(
                        f"[ThreatAnalyst][WARN] Unknown target_type={target_type!r} "
                        f"for action {action.get('id')} — skipping graph write"
                    )
    
            except Exception as exc:
                self._log(
                    f"[ThreatAnalyst][WARN] Could not stamp action {action.get('id')} "
                    f"on {target_type}={target_value}: {exc}"
                )

    # ── PERSISTENCE ───────────────────────────────────────────────────────────

    def _save_finding(self, finding: ResponderOutput) -> None:
        record = {
            "analysis_id":      str(uuid.uuid4()),
            "anchor_guid":      finding.anchor_guid,
            "produced_at":      datetime.utcnow().isoformat(),
            "verdict":          finding.verdict,
            "actions":          finding.actions,
            "raw_llm_response": finding.raw_llm_response,
        }
        try:
            with open(FINDINGS_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as exc:
            self._log(f"[ThreatAnalyst][WARN] Could not save finding: {exc}")

    def _print_finding(self, finding: ResponderOutput) -> None:
        verdict_symbol = {"MALICIOUS": "🔴", "SUSPICIOUS": "🟠"}.get(finding.verdict, "⚪")
        self._log(
            f"\n{'=' * 70}\n"
            f"[ANALYST FINDING]\n"
            f"  Anchor:   {finding.anchor_guid}\n"
            f"  Verdict:  {finding.verdict} {verdict_symbol}\n"
            f"  Actions:  {len(finding.actions)} response(s)\n"
        )
        if finding.actions:
            self._log("  EXECUTABLE ACTIONS:")
            for idx, action in enumerate(finding.actions, 1):
                self._log(
                    f"\n    [{idx}] PRIORITY {action.get('priority', 0)}: {action.get('type')}\n"
                    f"        target: {action.get('target_type')}={action.get('target_value')}\n"
                    f"        scope:  {action.get('scope')}\n"
                    f"        reason: {action.get('reason', '')}"
                )
        else:
            self._log("  ⚪ NO ACTIONS — monitoring only")
        self._log(f"{'=' * 70}\n")

    # ── STATS ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        return {**self._stats}
