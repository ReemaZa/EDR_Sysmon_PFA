"""
threat_analyst.py  —  Graph-based threat analyst (L4 detection layer).

RESPONSIBILITY:
    - Start a background daemon thread on construction
    - Every QUERY_INTERVAL seconds (tick):
        1. Scan Memgraph for ProcessInstance nodes meeting trigger condition
        2. Group triggered nodes by connectivity (union-find BFS)
        3. For each group: extract subgraph → run AnalystAgent → write verdict to all nodes
        4. Run pruning sweep
        5. Update in-progress set atomically

DESIGN NOTES:
    - No queue, no state machine. Single in-memory in-progress set protected by lock.
    - Connectivity grouping ensures attack chains stay together.
    - Verdict written to ALL nodes in group, not just anchor.
    - Pruning is reversible: new activity resets pruned + LLM properties.

CONFIGURATION:
    query_interval   : seconds between graph scans          (default 140)
    threat_threshold : minimum ProcessInstance.score        (default 4)
    max_subgraph_nodes: hard cap on nodes sent to analyst   (default 120)
    watch_hours      : hours before auto-pruning            (default 2)
"""
from __future__ import annotations
import sys
import json
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from gqlalchemy import Memgraph

from src.detection.l4_llm_detection.analyst_agent import AnalystAgent
from src.detection.l4_llm_detection.graph_extractor import GraphExtractor
from src.detection.l4_llm_detection.l4_models import InvestigationCase, AttackSummary
from src.graph.Graph_Builder import MEMGRAPH_HOST, MEMGRAPH_PORT


class ThreatAnalyst:
    """
    Graph-based threat analyst — starts automatically on construction.

    Lifecycle:
        analyst = ThreatAnalyst(query_interval=140, threat_threshold=4)
        # background thread is already running
        ...
        analyst.shutdown()   # call on exit
    """

    def __init__(
        self,
        query_interval:     int = 140,
        threat_threshold:   int = 4,
        max_subgraph_nodes: int = 120,
        watch_hours:        int = 2,
    ):
        self.query_interval    = query_interval
        self.threat_threshold  = threat_threshold
        self.max_subgraph_nodes = max_subgraph_nodes
        self.watch_hours       = watch_hours

        # ── Logging ──────────────────────────────────────────────────────
        self.log_file_path = f"logs/l4_analyst_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self._log_handle = open(self.log_file_path, "a", encoding="utf-8")
        self._log_lock = threading.Lock()

        # ── Components ───────────────────────────────────────────────────
        self._db        = Memgraph(host=MEMGRAPH_HOST, port=MEMGRAPH_PORT)
        self._extractor = GraphExtractor(self._db)
        self._analyst   = AnalystAgent()

        # ── In-progress coordination ─────────────────────────────────────
        self._in_progress: Set[str] = set()  # GUIDs currently being analysed
        self._in_progress_lock = threading.Lock()

        # ── Thread pool ──────────────────────────────────────────────────
        self._pool = ThreadPoolExecutor(
            max_workers=5,
            thread_name_prefix="L4Analyst"
        )

        # ── Stats ────────────────────────────────────────────────────────
        self._stats = {
            "ticks":           0,
            "triggers":        0,
            "groups":          0,
            "cases_analysed":  0,
            "findings":        0,
            "pruned_nodes":    0,
        }

        # ── Thread control ───────────────────────────────────────────────
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._loop,
            name="ThreatAnalyst",
            daemon=True,
        )

        # Start immediately
        self._thread.start()
        self._log(
            f"[ThreatAnalyst] Started — "
            f"interval={self.query_interval}s  threshold={self.threat_threshold}  "
            f"pool_workers=5  watch_hours={self.watch_hours}"
        )

    def _log(self, message: str):
        """Log to both file and console."""
        timestamp = datetime.utcnow().isoformat()
        formatted = f"[{timestamp}] {message}\n"

        with self._log_lock:
            self._log_handle.write(formatted)
            self._log_handle.flush()
            sys.__stdout__.write(formatted)
            sys.__stdout__.flush()

    # ── SHUTDOWN ──────────────────────────────────────────────────────────────

    def shutdown(self) -> None:
        """Gracefully shut down analyst and wait for in-flight LLM calls."""
        self._log("[ThreatAnalyst] Shutting down...")
        self._stop_event.set()
        
        # Wait for background loop to finish
        self._thread.join(timeout=self.query_interval + 5)
        
        # Shut down thread pool, wait for all in-flight calls
        self._pool.shutdown(wait=True)
        self._log("[ThreatAnalyst] Thread pool shut down.")
        
        # Close log file last
        with self._log_lock:
            self._log_handle.close()

    # ── BACKGROUND LOOP ───────────────────────────────────────────────────────

    def _loop(self) -> None:
        """Background thread: run _tick() every query_interval seconds."""
        self._log("[ThreatAnalyst] Background loop started.")
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception as exc:
                import traceback
                self._log(f"[ThreatAnalyst][ERROR] Tick failed: {exc}")
                traceback.print_exc()

            # Sleep in 1-second increments for responsive shutdown
            deadline = time.monotonic() + self.query_interval
            while time.monotonic() < deadline and not self._stop_event.is_set():
                time.sleep(1)

    # ── MAIN TICK ─────────────────────────────────────────────────────────────

    def _tick(self) -> None:
        """
        One complete analysis cycle:
        1. Scan graph for triggers
        2. Filter in-progress
        3. Group by connectivity
        4. Submit analysis jobs
        5. Run pruning sweep
        """
        self._stats["ticks"] += 1
        n = self._stats["ticks"]
        self._log(f"\n{'═' * 80}")
        self._log(f"[ThreatAnalyst] ══ Tick #{n} @ {datetime.utcnow().isoformat()} ══")

        # 1. Scan graph
        candidates = self._scan_graph()
        self._log(
            f"[ThreatAnalyst] Scanned: {len(candidates)} node(s) above "
            f"threshold={self.threat_threshold}"
        )
        self._stats["triggers"] += len(candidates)

        if not candidates:
            self._pruning_sweep()
            return

        # 2. Filter out in-progress GUIDs
        with self._in_progress_lock:
            filtered = [
                (guid, score) for guid, score in candidates
                if guid not in self._in_progress
            ]
        self._log(
            f"[ThreatAnalyst] After in-progress filter: {len(filtered)} candidate(s)"
        )

        if not filtered:
            self._pruning_sweep()
            return

        # 3. Group by connectivity
        groups = self._group_by_connectivity(filtered)
        self._log(f"[ThreatAnalyst] Connectivity grouping: {len(groups)} group(s)")
        self._stats["groups"] += len(groups)

        # 4. Filter out groups with any in-progress GUID
        with self._in_progress_lock:
            active_groups = [
                g for g in groups
                if not any(guid in self._in_progress for guid in g)
            ]
        self._log(
            f"[ThreatAnalyst] After group-level in-progress filter: "
            f"{len(active_groups)} group(s)"
        )

        # 5. Submit each group for analysis
        for group_set in active_groups:
            # Find the highest-scoring GUID as anchor
            anchor_guid = max(
                group_set,
                key=lambda g: next(
                    (s for gu, s in filtered if gu == g),
                    0
                )
            )
            trigger_score = next(
                (s for g, s in filtered if g == anchor_guid),
                0
            )

            case = InvestigationCase(
                case_id       = str(uuid.uuid4()),
                anchor_guid   = anchor_guid,
                group_guids   = group_set,
                trigger_score = trigger_score,
                trigger_time  = datetime.utcnow().isoformat(),
            )

            # Add all GUIDs to in-progress under lock
            with self._in_progress_lock:
                self._in_progress.update(group_set)

            self._log(
                f"[ThreatAnalyst] Submitting case {case.case_id[:8]} "
                f"anchor={anchor_guid[:12]}… group_size={len(group_set)}"
            )

            # Submit to thread pool
            self._pool.submit(self._analyse_group, case)
            self._stats["cases_analysed"] += 1

        # 6. Pruning sweep
        self._pruning_sweep()

        self._log(f"[ThreatAnalyst] Tick #{n} complete. Stats: {self._stats}")

    # ── SCAN GRAPH ────────────────────────────────────────────────────────────

    def _scan_graph(self) -> List[Tuple[str, int]]:
        """
        Find ProcessInstance nodes eligible for LLM analysis.

        Conditions (ALL must be true):
        - score >= threshold
        - ghost IS NULL OR ghost = false
        - pruned IS NULL OR pruned = false
        - At least one of:
          • llm_evaluated_at IS NULL (never evaluated)
          • score > llm_score_at_eval (score increased)
          • NEW ACTIVITY: ∃ edge where last_seen > llm_evaluated_at
        """
        try:
            rows = list(self._db.execute_and_fetch(
                """
                MATCH (p:ProcessInstance)
                WHERE p.score >= $threshold
                  AND (p.ghost IS NULL OR p.ghost = false)
                  AND (p.pruned IS NULL OR p.pruned = false)
                RETURN p.id AS guid, p.score AS score, p.llm_evaluated_at AS llm_evaluated_at
                ORDER BY p.score DESC
                """,
                {"threshold": self.threat_threshold},
            ))
        except Exception as exc:
            self._log(f"[ThreatAnalyst][SCAN FAIL] {exc}")
            return []

        # Post-process to filter by trigger condition (since EXISTS is not supported in Memgraph)
        candidates = []
        for row in rows:
            guid = row.get("guid")
            score = int(row.get("score") or 0)
            llm_eval = row.get("llm_evaluated_at")
            
            if not guid:
                continue
            
            # Condition 1: Never evaluated
            if llm_eval is None:
                candidates.append((guid, score))
                continue
            
            # Condition 2: Score increased since eval
            llm_score_at_eval = row.get("llm_score_at_eval")
            if llm_score_at_eval is not None:
                if score > llm_score_at_eval:
                    candidates.append((guid, score))
                    continue
            
            # Condition 3: New edges since eval (check separately)
            try:
                new_edge_rows = list(self._db.execute_and_fetch(
                    """
                    MATCH (p:ProcessInstance {id: $guid})-[r]->(n)
                    WHERE r.last_seen > $eval_time
                    RETURN count(r) AS edge_count
                    """,
                    {"guid": guid, "eval_time": llm_eval},
                ))
                if new_edge_rows and new_edge_rows[0].get("edge_count", 0) > 0:
                    candidates.append((guid, score))
            except Exception:
                pass  # If check fails, skip this node
        
        return candidates

    # ── CONNECTIVITY GROUPING ─────────────────────────────────────────────────

    def _group_by_connectivity(
        self,
        candidates: List[Tuple[str, int]],
    ) -> List[Set[str]]:
        """
        Group candidate GUIDs by connectivity. Two GUIDs belong to the same group
        if there's a path between them via CHILD_OF|CREATED|INJECTED_THREAD|ACCESSED_MEMORY|TAMPERED
        within 6 hops.

        Uses union-find to partition candidates into groups.
        """
        if not candidates:
            return []

        guid_list = [g for g, _ in candidates]
        if not guid_list:
            return []

        # Union-find
        parent: Dict[str, str] = {g: g for g in guid_list}

        def find(x: str) -> str:
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]

        def union(x: str, y: str):
            rx, ry = find(x), find(y)
            if rx != ry:
                parent[rx] = ry

        # For each pair, check connectivity
        for i, guid_a in enumerate(guid_list):
            for guid_b in guid_list[i + 1:]:
                if find(guid_a) == find(guid_b):
                    continue

                # Check if path exists
                try:
                    rows = list(self._db.execute_and_fetch(
                        """
                        MATCH p = shortestPath(
                            (a:ProcessInstance {id: $guid_a})-
                            [:CHILD_OF|CREATED|INJECTED_THREAD|ACCESSED_MEMORY|TAMPERED*1..6]-
                            (b:ProcessInstance {id: $guid_b})
                        )
                        RETURN p IS NOT NULL AS connected
                        """,
                        {"guid_a": guid_a, "guid_b": guid_b},
                    ))
                    if rows and rows[0].get("connected"):
                        union(guid_a, guid_b)
                except Exception:
                    pass

        # Group by root
        groups_dict: Dict[str, Set[str]] = {}
        for guid in guid_list:
            root = find(guid)
            if root not in groups_dict:
                groups_dict[root] = set()
            groups_dict[root].add(guid)

        return list(groups_dict.values())

    # ── ANALYSIS (runs in thread pool) ────────────────────────────────────────

    def _analyse_group(self, case: InvestigationCase) -> None:
        """
        Analyse one connectivity group. Runs in worker thread.

        1. Extract subgraph
        2. If subgraph is None → write SUSPICIOUS to all nodes
        3. Call analyst → write verdict to all nodes
        4. Remove from in-progress
        """
        try:
            self._log(
                f"[ThreatAnalyst] _analyse_group START case={case.case_id[:8]} "
                f"anchor={case.anchor_guid[:12]}… group_size={len(case.group_guids)}"
            )

            # 1. Extract subgraph
            to_investigate = case.group_guids - {case.anchor_guid}
            subgraph = self._extractor.extract(
                anchor_guid    = case.anchor_guid,
                to_investigate = to_investigate,
            )

            # 2. Handle null subgraph
            if subgraph is None:
                self._log(
                    f"[ThreatAnalyst] No subgraph returned for case {case.case_id[:8]}  "
                    f"marking all nodes SUSPICIOUS"
                )
                self._write_verdict_to_group(
                    case.group_guids,
                    verdict         = "SUSPICIOUS",
                    score_at_eval   = case.trigger_score,
                )
                return

            # 3. Log subgraph details
            self._log(
                f"[ThreatAnalyst] Extracted subgraph for case {case.case_id[:8]}  "
                f"nodes={subgraph.total_nodes}  edges={subgraph.total_edges}"
            )
            self._log_subgraph_nodes(subgraph)

            # 4. Log the prompt being used
            self._log_analyst_prompt(case, subgraph)

            # 5. Call analyst
            self._log(
                f"[ThreatAnalyst] Calling analyst for case {case.case_id[:8]}  "
                f"passing {len(subgraph.instances)} instances "
                f"{len(subgraph.edges)} edges"
            )
            summary = self._analyst.analyse(case, subgraph)

            # 6. Write verdict to all nodes in group
            self._write_verdict_to_group(
                case.group_guids,
                verdict         = summary.verdict,
                score_at_eval   = subgraph.anchor_score,
            )

            self._log(
                f"[ThreatAnalyst] Verdict written for case {case.case_id[:8]}  "
                f"verdict={summary.verdict}  severity={summary.severity}  "
                f"confidence={summary.confidence}"
            )
            self._stats["findings"] += 1

            # 7. Log finding summary
            self._print_finding(summary)

        except Exception as exc:
            import traceback
            self._log(f"[ThreatAnalyst][ERROR] _analyse_group failed: {exc}")
            traceback.print_exc()

        finally:
            # Always remove from in-progress
            with self._in_progress_lock:
                self._in_progress -= case.group_guids
            self._log(
                f"[ThreatAnalyst] _analyse_group END case={case.case_id[:8]} "
                f"removed from in-progress"
            )

    # ── VERDICT WRITE ─────────────────────────────────────────────────────────

    def _write_verdict_to_group(
        self,
        group_guids: Set[str],
        verdict: str,
        score_at_eval: int,
    ) -> None:
        """Write LLM verdict to all nodes in the group."""
        now = datetime.utcnow().isoformat()
        try:
            self._db.execute(
                """
                UNWIND $guids AS guid
                MATCH (p:ProcessInstance {id: guid})
                SET p.llm_verdict       = $verdict,
                    p.llm_evaluated_at  = $evaluated_at,
                    p.llm_score_at_eval = $score_at_eval
                """,
                {
                    "guids": list(group_guids),
                    "verdict": verdict,
                    "evaluated_at": now,
                    "score_at_eval": score_at_eval,
                },
            )
        except Exception as exc:
            self._log(f"[ThreatAnalyst][WRITE FAIL] {exc}")

    # ── PRUNING SWEEP ────────────────────────────────────────────────────────

    def _pruning_sweep(self) -> None:
        """
        Prune nodes that:
        - Were LLM evaluated
        - Have NOT been pruned yet
        - Score has NOT changed since eval
        - Have NO new edges since eval
        - Last eval was > watch_hours ago
        """
        try:
            watch_threshold = (
                datetime.utcnow() - timedelta(hours=self.watch_hours)
            ).isoformat()

            # First, get all candidates (evaluated, not pruned, score unchanged, old eval)
            rows = list(self._db.execute_and_fetch(
                """
                MATCH (p:ProcessInstance)
                WHERE p.llm_evaluated_at IS NOT NULL
                  AND (p.pruned IS NULL OR p.pruned = false)
                  AND p.score = p.llm_score_at_eval
                  AND p.llm_evaluated_at < $threshold
                RETURN p.id AS guid, p.llm_evaluated_at AS eval_time
                """,
                {"threshold": watch_threshold},
            ))

            pruned_count = 0
            for row in rows:
                guid = row.get("guid")
                eval_time = row.get("eval_time")
                
                if not guid:
                    continue
                
                # Check for new edges since eval (post-filter since NOT EXISTS not supported)
                try:
                    edge_check = list(self._db.execute_and_fetch(
                        """
                        MATCH (p:ProcessInstance {id: $guid})-[r]->(n)
                        WHERE r.last_seen > $eval_time
                        RETURN count(r) AS edge_count
                        """,
                        {"guid": guid, "eval_time": eval_time},
                    ))
                    
                    # If there are new edges, skip pruning this node
                    if edge_check and edge_check[0].get("edge_count", 0) > 0:
                        continue
                except Exception:
                    continue  # If check fails, skip pruning
                
                # All conditions met: prune this node
                try:
                    self._db.execute(
                        "MATCH (p:ProcessInstance {id: $guid}) SET p.pruned = true",
                        {"guid": guid},
                    )
                    pruned_count += 1
                except Exception as exc:
                    self._log(f"[ThreatAnalyst][PRUNE FAIL] {guid}: {exc}")

            if pruned_count > 0:
                self._log(
                    f"[ThreatAnalyst] Pruning sweep: {pruned_count} nodes pruned"
                )
                self._stats["pruned_nodes"] += pruned_count

        except Exception as exc:
            self._log(f"[ThreatAnalyst][PRUNE SWEEP FAIL] {exc}")

    # ── LOGGING HELPERS ──────────────────────────────────────────────────────

    def _log_subgraph_nodes(self, subgraph) -> None:
        """Log details of instances in the subgraph."""
        lines = [
            f"[SUBGRAPH NODES]",
            f"  Instances ({len(subgraph.instances)}):",
        ]
        for inst in subgraph.instances:
            tag = "ANCHOR" if inst.guid == subgraph.anchor_guid else ""
            lines.append(
                f"    {inst.guid[:16]}… score={inst.score} "
                f"ghost={inst.ghost} {tag}"
            )
        lines.append(f"  Artifacts ({len(subgraph.artifacts)})")
        lines.append(f"  Edges ({len(subgraph.edges)})")

        self._log("\n".join(lines))

    def _log_analyst_prompt(self, case: InvestigationCase, subgraph) -> None:
        """Log the prompt that was built for the analyst."""
        from src.detection.l4_llm_detection.analyst_agent import AnalystAgent
        
        prompt = AnalystAgent()._build_prompt(case, subgraph)
        
        # Write full prompt to timestamped file for debugging
        prompt_file = f"logs/analyst_prompt_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(prompt_file, "w", encoding="utf-8") as f:
                f.write(prompt)
            self._log(f"[ThreatAnalyst] Prompt saved to {prompt_file} ({len(prompt)} chars)")
        except Exception as exc:
            self._log(f"[ThreatAnalyst][WARN] Could not save prompt: {exc}")

        # Log first 500 chars to console
        prompt_summary = prompt[:500].replace("\n", " ")
        self._log(f"[ThreatAnalyst] Prompt preview: {prompt_summary}…")

    def _print_finding(self, summary: AttackSummary) -> None:
        """Log the final attack summary."""
        symbol = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
        }.get(summary.severity, "⚪")

        lines = [
            f"{'=' * 80}",
            f"[L4 FINDING]",
            f"  Case:       {summary.case_id}",
            f"  Anchor:     {summary.anchor_guid}",
            f"  Verdict:    {summary.verdict}  {symbol} {summary.severity}  "
            f"(confidence: {summary.confidence})",
            f"  Techniques: {', '.join(summary.mitre_techniques) or 'none'}",
            f"  Tactics:    {', '.join(summary.mitre_tactics) or 'none'}",
            f"  Summary:    {summary.summary[:200]}",
            f"  Attack Chain Steps: {len(summary.attack_chain)}",
            f"  IOCs: {len(summary.iocs)} identified",
            f"  Files: {len(summary.files)} touched",
            f"{'=' * 80}",
        ]
        self._log("\n".join(lines))

    # ── STATS ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Return current analysis statistics."""
        return {
            **self._stats,
            "in_progress_count": len(self._in_progress),
            "timestamp": datetime.utcnow().isoformat(),
        }
