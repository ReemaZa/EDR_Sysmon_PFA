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
    
            self._apply_verdict(subgraph, finding)
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

    # ── CONNECTED COMPONENTS ──────────────────────────────────────────────────

    def _split_components(self, subgraph: SubgraphContext) -> List[SubgraphContext]:
        """
        Split a SubgraphContext into independent connected components
        using union-find on the edge list.
        Each component becomes its own SubgraphContext for a separate LLM call.
        """
        all_ids = (
            {i.guid for i in subgraph.instances} |
            {a.id   for a in subgraph.artifacts}
        )

        # Union-Find
        parent = {n: n for n in all_ids}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]   # path compression
                x = parent[x]
            return x

        def union(a: str, b: str):
            parent[find(a)] = find(b)

        for edge in subgraph.edges:
            if edge.src_id in parent and edge.dst_id in parent:
                union(edge.src_id, edge.dst_id)

        # Group node IDs by their root
        groups: Dict[str, Set[str]] = {}
        for node_id in all_ids:
            root = find(node_id)
            groups.setdefault(root, set()).add(node_id)

        # Build one SubgraphContext per group
        components: List[SubgraphContext] = []
        for node_ids in groups.values():
            instances = [i for i in subgraph.instances if i.guid  in node_ids]
            artifacts = [a for a in subgraph.artifacts  if a.id   in node_ids]
            edges     = [e for e in subgraph.edges
                         if e.src_id in node_ids and e.dst_id in node_ids]
            templates = {
                h: t for h, t in subgraph.templates.items()
                if any(i.template_hash == h for i in instances)
            }

            # Pick anchor = highest scoring instance in this component
            anchor_inst = max(instances, key=lambda i: i.score)

            # Rebuild process tree for this component only
            process_tree = {
                guid: children
                for guid, children in subgraph.process_tree.items()
                if guid in node_ids
            }
            tree_roots = [
                guid for guid in subgraph.tree_roots
                if guid in node_ids
            ]

            components.append(SubgraphContext(
                anchor_guid       = anchor_inst.guid,
                anchor_score      = anchor_inst.score,
                instances         = instances,
                templates         = templates,
                artifacts         = artifacts,
                edges             = edges,
                timeline          = [
                    e for e in subgraph.timeline
                    if e.get("src") in node_ids or e.get("dst") in node_ids
                ],
                has_ghost_parents = any(i.ghost for i in instances),
                total_nodes       = len(instances) + len(artifacts),
                total_edges       = len(edges),
                unvisited_guids   = set(),
                process_tree      = process_tree,
                tree_roots        = tree_roots,
            ))

        # Sort components by anchor score descending so highest-risk runs first
        components.sort(key=lambda c: -c.anchor_score)
        return components

    # ── APPLY VERDICT ─────────────────────────────────────────────────────────

    def _apply_verdict(self, component: SubgraphContext, result: ResponderOutput) -> None:
        """
        Write last_analysed_score, last_verdict, last_analysed_at
        back onto every ProcessInstance node in this component.
        """
        ts = datetime.utcnow().isoformat()
        for inst in component.instances:
            try:
                self._db.execute(
                    """
                    MATCH (p:ProcessInstance {id: $guid})
                    SET p.last_analysed_score = p.score,
                        p.last_verdict        = $verdict,
                        p.last_analysed_at    = $ts
                    """,
                    {"guid": inst.guid, "verdict": result.verdict, "ts": ts},
                )
            except Exception as exc:
                self._log(f"[ThreatAnalyst][WARN] Could not apply verdict to {inst.guid}: {exc}")

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
