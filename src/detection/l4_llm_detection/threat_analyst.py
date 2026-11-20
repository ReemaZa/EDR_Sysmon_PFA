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
from src.detection.l4_llm_detection.action_executor import ActionExecutor
from src.core.config import (
    ACTION_MODE,
    ACTIONED_NODES_FILE,
    ACTIONED_NODES_LOCK,
    PENDING_APPROVALS_FILE,
    PENDING_APPROVALS_LOCK,
    new_record_id,
    normalize_action_mode,
)

FINDINGS_FILE = "l4_findings.json"
# PENDING_APPROVALS_FILE, ACTIONED_NODES_FILE and ACTIONED_NODES_LOCK now live in
# src/core/config.py (shared with the remediation module) and are imported above,
# so existing `from ...threat_analyst import ACTIONED_NODES_FILE` imports still work.

# Consecutive "quiet" ticks (no new node above threshold) after which the analyst
# asks for a remediation sweep (consumed by agent.py in live mode).
QUIET_TICKS_FOR_REMEDIATION = 10


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
        action_executor_mode: str = ACTION_MODE,
    ):
        self.query_interval     = query_interval
        self.threat_threshold   = threat_threshold
        self.max_subgraph_nodes = max_subgraph_nodes
        self.action_executor = ActionExecutor(mode=normalize_action_mode(action_executor_mode))
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

        # ── Remediation trigger state (used by live mode in agent.py) ─────────
        self._quiet_ticks        = 0   # incremented each tick with no candidates
        self.quiet_ticks_required = QUIET_TICKS_FOR_REMEDIATION
        self._remediation_requested = threading.Event()  # set when threshold met

        # ── Idle tracking (used by wait_until_idle) ───────────────────────────
        # A tick is "clean" when its scan found nothing left to analyse. The
        # analyst is idle w.r.t. a moment T when no tick is running and a clean
        # tick that STARTED after T has finished: everything scored before T has
        # then been analysed and its actions written to actioned_nodes.jsonl.
        self._idle_cv               = threading.Condition()
        self._tick_in_progress      = False
        self._last_clean_tick_start = 0.0          # time.monotonic() of that tick
        self._wake_event            = threading.Event()   # "tick now" request

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

    def shutdown(self):
        self._log("[ThreatAnalyst] Shutting down...")

        self._stop_event.set()

        # stop loop first
        self._thread.join(timeout=self.query_interval + 5)

        # WAIT for all actions
        if self.action_executor:
            self._log("[ThreatAnalyst] Waiting for actions to finish...")
            self.action_executor.wait_for_completion()

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

            # Sleep in 1-second increments so shutdown() is responsive;
            # wait_until_idle() can cut the sleep short to get a fresh scan.
            deadline = time.monotonic() + self.query_interval
            while time.monotonic() < deadline and not self._stop_event.is_set():
                if self._wake_event.wait(timeout=1):
                    self._wake_event.clear()
                    break

    def consume_remediation_request(self) -> bool:
        """
        Returns True (and clears the flag) if a remediation run was requested
        since the last call.  Thread-safe.
        """
        if self._remediation_requested.is_set():
            self._remediation_requested.clear()
            return True
        return False

    def wait_until_idle(self, timeout: float = 300.0) -> bool:
        """
        Block until the analyst has nothing left to do for everything scored in
        the graph up to now, or until `timeout` seconds pass.

        Forces an immediate tick (instead of waiting for the next interval) and
        returns True once a tick that started after this call has found no
        candidate above threshold. Returns False on timeout or if the analyst
        was shut down first. Safe to call from any thread.
        """
        start = time.monotonic()
        deadline = start + timeout
        self._wake_event.set()
        with self._idle_cv:
            while True:
                if self._stop_event.is_set():
                    return False
                if not self._tick_in_progress and self._last_clean_tick_start > start:
                    return True
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                # A tick that was already running when we asked saw an older
                # graph; make sure another one follows it.
                self._wake_event.set()
                self._idle_cv.wait(timeout=min(1.0, remaining))

    # ── TICK ──────────────────────────────────────────────────────────────────

    def _tick(self) -> None:
        """Run one scan/analyse cycle and record whether it came out clean."""
        started = time.monotonic()
        with self._idle_cv:
            self._tick_in_progress = True
        clean = False
        try:
            clean = self._run_tick()
        finally:
            with self._idle_cv:
                self._tick_in_progress = False
                if clean:
                    self._last_clean_tick_start = started
                self._idle_cv.notify_all()

    def _run_tick(self) -> bool:
        """Body of one tick. Returns True if nothing was above threshold."""
        self._stats["ticks"] += 1
        n = self._stats["ticks"]
        self._log(f"\n[ThreatAnalyst] ══ Tick #{n} @ {datetime.utcnow().isoformat()} ══")
    
        candidates = self._scan_graph()
        self._log(f"[ThreatAnalyst] {len(candidates)} candidate(s) above threshold={self.threat_threshold}")
        if not candidates:
            self._quiet_ticks += 1
            self._log(
                f"[ThreatAnalyst] Quiet tick #{self._quiet_ticks} "
                f"(no nodes above threshold)"
            )
            if self._quiet_ticks >= self.quiet_ticks_required:
                self._log(
                    f"[ThreatAnalyst] {self.quiet_ticks_required} consecutive quiet ticks — "
                    "signalling remediation."
                )
                self._quiet_ticks = 0          # reset so it doesn't fire again immediately
                self._remediation_requested.set()
            return True

        # candidates found — reset quiet counter
        self._quiet_ticks = 0
    
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
            # The anchor is always consumed, even if the extractor did not return
            # it as an instance - otherwise this loop would never terminate.
            visited = {i.guid for i in subgraph.instances} | {anchor_guid}
            remaining = [g for g in remaining if g not in visited]
            # unvisited_guids stay in remaining naturally since they weren't visited
            # ── NEW: execute containment actions in a parallel thread ──
            if finding.verdict in ("MALICIOUS","SUSPICIOUS") and finding.actions:
                if self.action_executor.mode == "automatic":
                    self.action_executor.execute_async(finding.actions, finding.anchor_guid)
                elif self.action_executor.mode == "approval":
                    
                    self._save_pending_approval(finding)

        return False

    def _save_pending_approval(self, finding: ResponderOutput) -> None:
        record = {
            "analysis_id": finding.analysis_id,
            "anchor_guid": finding.anchor_guid,
            "verdict": finding.verdict,
            "actions": finding.actions,
            "produced_at": datetime.utcnow().isoformat(),
            "executed": False,
            "source": "analyst",
        }
        try:
            with PENDING_APPROVALS_LOCK, open(PENDING_APPROVALS_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
            self._log(f"[ThreatAnalyst] Pending approval saved → analysis_id={finding.analysis_id}")
        except Exception as exc:
            self._log(f"[ThreatAnalyst][WARN] Could not save pending approval: {exc}")

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

    def _apply_verdict(self, component, result, investigated_guids):
        ts = datetime.utcnow().isoformat()

        guids_to_stamp = [
            inst.guid for inst in component.instances
            if inst.guid in investigated_guids
        ]

        if not guids_to_stamp:
            return

        # One query for all nodes instead of one per node
        self._db.execute(
            """
            UNWIND $guids AS guid
            MATCH (p:ProcessInstance {id: guid})
            SET p.last_analysed_score = p.score,
                p.last_analysed_at    = $ts
            """,
            {"guids": guids_to_stamp, "ts": ts},
        )

    # ── APPLY GRAPH ACTIONS ───────────────────────────────────────────────────────

    def _apply_graph_actions(self, result: ResponderOutput) -> None:
        """
        Write action tags back to their target nodes in the graph.
        Uses UNWIND batching — one query per node type instead of one per action.
        """
        if not result.actions:
            return

        ts = datetime.utcnow().isoformat()

        # Group actions by target_type
        from collections import defaultdict
        groups = defaultdict(list)

        for action in result.actions:
            target_type  = action.get("target_type", "")
            target_value = action.get("target_value", "")
            if not target_value:
                continue
            groups[target_type].append({
                "val":         target_value,
                "action_type": action.get("type", "unknown"),
                "priority":    action.get("priority", 0),
                "reason":      action.get("reason", ""),
            })

        # Map: target_type → (label, id_field)
        TYPE_MAP = {
            "guid":     ("ProcessInstance", "id"),
            "file":     ("File",            "id"),
            "ip":       ("Network",         "id"),
            "domain":   ("DNS",             "id"),
            "registry": ("Registry",        "id"),
            "user":     ("User",            "id"),
            "host":     ("Host",            "id"),
        }

        for target_type, actions_list in groups.items():
            if target_type not in TYPE_MAP:
                self._log(
                    f"[ThreatAnalyst][WARN] Unknown target_type={target_type!r} "
                    f"— skipping {len(actions_list)} action(s)"
                )
                continue

            label, id_field = TYPE_MAP[target_type]

            try:
                # Build query with proper syntax
                query = f"""
                UNWIND $actions AS a
                MATCH (n:{label} {{{id_field}: a.val}})
                SET n.pending_action    = a.action_type,
                    n.action_reason     = a.reason,
                    n.action_stamped_at = $ts
                RETURN count(n) AS matched
                """
                result_rows = list(self._db.execute_and_fetch(query, {"actions": actions_list, "ts": ts}))
                matched = result_rows[0]["matched"] if result_rows else 0
                
                self._log(
                    f"[ThreatAnalyst][ACTION BATCH] {label}: {matched}/{len(actions_list)} nodes updated"
                )
                
                if matched == 0:
                    self._log(
                        f"[ThreatAnalyst][CRITICAL] No {label} nodes matched! "
                        f"Sample values: {[a['val'][:40] for a in actions_list[:2]]}"
                    )
                
                for a in actions_list:
                    self._log(
                        f"[ThreatAnalyst][ACTION] [{a['action_type']}] "
                        f"→ {label} {a['val'][:40]}"
                    )

            except Exception as exc:
                self._log(
                    f"[ThreatAnalyst][ERROR] Batch stamp failed for "
                    f"target_type={target_type}: {exc}"
                )
                import traceback
                self._log(traceback.format_exc())
                
                # Fallback: retry one by one
                for a in actions_list:
                    try:
                        fallback_query = f"""
                        MATCH (n:{label} {{{id_field}: $val}})
                        SET n.pending_action    = $action_type,
                            n.action_reason     = $reason,
                            n.action_stamped_at = $ts
                        RETURN count(n) AS cnt
                        """
                        fallback_result = list(self._db.execute_and_fetch(
                            fallback_query,
                            {
                                "val":         a["val"],
                                "action_type": a["action_type"],
                                "reason":      a["reason"],
                                "ts":          ts,
                            },
                        ))
                        cnt = fallback_result[0]["cnt"] if fallback_result else 0
                        if cnt == 0:
                            self._log(
                                f"[ThreatAnalyst][WARN] No node found for "
                                f"{label}.{id_field}={a['val']}"
                            )
                    except Exception as inner_exc:
                        self._log(
                            f"[ThreatAnalyst][ERROR] Single fallback also failed "
                            f"for {label} {a['val']}: {inner_exc}"
                        )

        # Write durable record to actioned_nodes.jsonl (after all graph stamping)
        self._append_actioned_nodes(result, ts)           
    
    
    def _append_actioned_nodes(
        self, result: ResponderOutput, ts: str
    ) -> None:
        """
        Append one entry per action to actioned_nodes.jsonl.
        Key is (action_type, target_value).  remediation_handled starts False.
        This is the durable record for the remediation pipeline.
        """
        if not result.actions:
            return

        # Load existing records keyed by (action_type, target_value) so we can
        # deduplicate — if the same key exists we still append (new tick, new
        # entry with remediation_handled=False) per the spec.
        records = []
        for action in result.actions:
            action_type  = action.get("type", "unknown")
            target_type  = action.get("target_type", "")
            target_value = action.get("target_value", "")
            if not target_value:
                continue
            record = {
                "record_id":           new_record_id(),
                "guid":                result.anchor_guid,
                "action_type":         action_type,
                "target_type":         target_type,
                "target_value":        target_value,
                "reason":              action.get("reason", ""),
                "stamped_at":          ts,
                "remediation_handled": False,
            }
            records.append(record)

        if not records:
            return

        try:
            with ACTIONED_NODES_LOCK, open(ACTIONED_NODES_FILE, "a", encoding="utf-8") as f:
                for rec in records:
                    f.write(json.dumps(rec) + "\n")
            self._log(
                f"[ThreatAnalyst] Appended {len(records)} record(s) "
                f"to {ACTIONED_NODES_FILE}"
            )
        except Exception as exc:
            self._log(
                f"[ThreatAnalyst][WARN] Could not append to "
                f"{ACTIONED_NODES_FILE}: {exc}"
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
