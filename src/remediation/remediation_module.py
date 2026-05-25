"""
remediation_module.py  —  Orchestrator: runs the full remediation pipeline.

PIPELINE (called once, after log ingestion is complete + 60s grace period)
──────────────────────────────────────────────────────────────────────────
  1. IncidentCollector  — query Memgraph for stamped GUIDs (ProcessInstance)
                          AND stamped File / Network / DNS nodes
  2. IncidentGrouper    — union-find clustering via PAT parent chains
  3. LineageBuilder     — full ancestry + blast radius from PAT
  4. ContextBuilder     — assemble LLM payload, including analyst_file_actions
                          and analyst_network_actions scoped to blast radius
  5. RemediationAgent   — ReAct tool-calling loop → RemediationReport

TRIGGER
-------
Called from agent.py after log replay finishes:
    run_remediation(pat=process_artifact_tree)

Sleeps GRACE_PERIOD_SECONDS first so the AnalystAgent background thread
can stamp all pending_actions before we query Memgraph.

CHANGES vs previous version
----------------------------
1. IncidentCollector.get_actioned_guids — unchanged.

2. NEW: IncidentCollector.get_analyst_file_actions(db, logger)
   Queries File nodes with pending_action IS NOT NULL.
   Returns list of dicts: {path, action_type, action_reason,
                            action_stamped_at, source_process_guid}.
   `source_process_guid` is resolved by following the CREATED/WROTE
   relationship back to a ProcessInstance so we can scope files to
   incident blast radii.

3. NEW: IncidentCollector.get_analyst_network_actions(db, logger)
   Queries Network nodes (ip_block) and DNS nodes (dns_block) with
   pending_action IS NOT NULL.
   Returns list of dicts: {value, action_type, action_reason,
                            action_stamped_at, ioc_type}.

4. ContextBuilder.build_context — now accepts analyst_file_actions and
   analyst_network_actions lists.  Filters them to only entries whose
   source_process_guid appears in the blast radius of the current incident
   (or whose value can be reverse-looked-up via PAT into the blast radius).
   Adds two new top-level keys to the payload:
     "analyst_file_actions"    : scoped list
     "analyst_network_actions" : scoped list

5. ContextBuilder._simulate_executed_actions — fixed: now also includes
   entries from analyst_file_actions and analyst_network_actions with
   the REAL target_value (file path / IP / domain) instead of always
   using the process GUID.

6. run_remediation — now collects file + network actions upfront and
   passes them through ContextBuilder into RemediationToolRegistry so
   that tool results can carry inline already_actioned_by_analyst flags.

7. RemediationToolRegistry is now constructed with analyst_actioned_files
   and analyst_actioned_network dicts so tools can annotate results inline.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from gqlalchemy import Memgraph

from src.PAT.pat_builder import PATBuilder
from src.graph.Graph_Builder import MEMGRAPH_HOST, MEMGRAPH_PORT
from src.remediation.remediation_logger import RemediationLogger
from src.remediation.remediation_models import (
    IncidentGroup,
    IncidentLineage,
    RemediationReport,
)
from src.remediation.remediation_tools import RemediationToolRegistry
from src.remediation.remediation_agent import RemediationAgent

GRACE_PERIOD_SECONDS = 60


# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — INCIDENT COLLECTOR
# ══════════════════════════════════════════════════════════════════════════════

class IncidentCollector:
    """
    Queries Memgraph for all nodes the AnalystAgent stamped with a
    pending_action:
      - ProcessInstance nodes  (unchanged)
      - File nodes             (NEW — file_quarantine / file_deletion)
      - Network nodes          (NEW — ip_block)
      - DNS nodes              (NEW — dns_block)

    When the Response Module is complete, update the ProcessInstance query
    to filter on action_executed IS NOT NULL instead of pending_action IS NOT NULL.
    """

    @staticmethod
    def get_actioned_guids(db: Memgraph, logger: RemediationLogger) -> List[str]:
        """
        Return every ProcessInstance GUID that has a non-null pending_action.

        Parameters
        ----------
        db     : active Memgraph connection.
        logger : shared RemediationLogger for this pipeline run.

        Returns
        -------
        List of GUID strings, deduplicated. Empty list on DB error.
        """
        logger.info(
            "Querying Memgraph for ProcessInstance nodes "
            "with pending_action IS NOT NULL ..."
        )

        try:
            rows = list(db.execute_and_fetch(
                """
                MATCH (p:ProcessInstance)
                WHERE p.pending_action IS NOT NULL
                  AND p.pending_action <> ''
                RETURN
                    p.id             AS guid,
                    p.pending_action AS pending_action,
                    p.score          AS score,
                    p.alive          AS alive
                """
            ))
        except Exception as exc:
            logger.error("Memgraph query failed", exc)
            return []

        guids = [row["guid"] for row in rows if row.get("guid")]

        # Log every node returned so you can verify they are the right ones
        logger.info(f"Found {len(guids)} actioned GUID(s).")
        if rows:
            logger.data(
                "Actioned nodes returned from Memgraph",
                [
                    {
                        "guid":           row.get("guid", ""),
                        "pending_action": row.get("pending_action", ""),
                        "score":          row.get("score", 0),
                        "alive":          row.get("alive", True),
                    }
                    for row in rows
                ],
            )

        return guids

    @staticmethod
    def get_analyst_file_actions(
        db: Memgraph, logger: RemediationLogger
    ) -> List[Dict[str, Any]]:
        """
        Query Memgraph for File nodes the analyst stamped with pending_action.

        Returns
        -------
        List of dicts:
          {
            "path":                str,   # File.id (the file path)
            "action_type":         str,   # "file_quarantine" | "file_deletion"
            "action_reason":       str,
            "action_stamped_at":   str,
            "source_process_guid": str,   # GUID of the ProcessInstance that
                                          # CREATED or WROTE this file, or ""
                                          # if the relationship is missing.
          }
        """
        logger.info(
            "Querying Memgraph for File nodes with pending_action IS NOT NULL ..."
        )

        try:
            # Try to follow CREATED/WROTE relationships back to the source process.
            # The OPTIONAL MATCH means we still get the file even if the relationship
            # is absent (e.g. file was added by static rule, not a live process).
            rows = list(db.execute_and_fetch(
                """
                MATCH (f:File)
                WHERE f.pending_action IS NOT NULL
                  AND f.pending_action <> ''
                OPTIONAL MATCH (p:ProcessInstance)-[:CREATED|WROTE]->(f)
                RETURN
                    f.id                AS path,
                    f.pending_action    AS action_type,
                    f.action_reason     AS action_reason,
                    f.action_stamped_at AS action_stamped_at,
                    p.id                AS source_process_guid
                """
            ))
        except Exception as exc:
            logger.error("Memgraph File node query failed", exc)
            return []

        result = [
            {
                "path":                row.get("path", ""),
                "action_type":         row.get("action_type", ""),
                "action_reason":        row.get("action_reason", ""),
                "action_stamped_at":   row.get("action_stamped_at", ""),
                "source_process_guid": row.get("source_process_guid") or "",
            }
            for row in rows
            if row.get("path")
        ]

        logger.info(f"Found {len(result)} analyst-actioned File node(s).")
        if result:
            logger.data("Analyst-actioned File nodes", result)

        return result

    @staticmethod
    def get_analyst_network_actions(
        db: Memgraph, logger: RemediationLogger
    ) -> List[Dict[str, Any]]:
        """
        Query Memgraph for Network (ip_block) and DNS (dns_block) nodes the
        analyst stamped with pending_action.

        Returns
        -------
        List of dicts:
          {
            "value":             str,   # IP address or domain name (node .id)
            "action_type":       str,   # "ip_block" | "dns_block"
            "action_reason":     str,
            "action_stamped_at": str,
            "ioc_type":          str,   # "ip" | "domain"
          }
        """
        logger.info(
            "Querying Memgraph for Network/DNS nodes with "
            "pending_action IS NOT NULL ..."
        )

        results = []

        # Network nodes (ip_block)
        try:
            rows = list(db.execute_and_fetch(
                """
                MATCH (n:Network)
                WHERE n.pending_action IS NOT NULL
                  AND n.pending_action <> ''
                RETURN
                    n.id                AS value,
                    n.pending_action    AS action_type,
                    n.action_reason     AS action_reason,
                    n.action_stamped_at AS action_stamped_at
                """
            ))
            for row in rows:
                if row.get("value"):
                    results.append({
                        "value":             row.get("value", ""),
                        "action_type":       row.get("action_type", ""),
                        "action_reason":     row.get("action_reason", ""),
                        "action_stamped_at": row.get("action_stamped_at", ""),
                        "ioc_type":          "ip",
                    })
        except Exception as exc:
            logger.error("Memgraph Network node query failed", exc)

        # DNS nodes (dns_block)
        try:
            rows = list(db.execute_and_fetch(
                """
                MATCH (d:DNS)
                WHERE d.pending_action IS NOT NULL
                  AND d.pending_action <> ''
                RETURN
                    d.id                AS value,
                    d.pending_action    AS action_type,
                    d.action_reason     AS action_reason,
                    d.action_stamped_at AS action_stamped_at
                """
            ))
            for row in rows:
                if row.get("value"):
                    results.append({
                        "value":             row.get("value", ""),
                        "action_type":       row.get("action_type", ""),
                        "action_reason":     row.get("action_reason", ""),
                        "action_stamped_at": row.get("action_stamped_at", ""),
                        "ioc_type":          "domain",
                    })
        except Exception as exc:
            logger.error("Memgraph DNS node query failed", exc)

        logger.info(f"Found {len(results)} analyst-actioned Network/DNS node(s).")
        if results:
            logger.data("Analyst-actioned Network/DNS nodes", results)

        return results


# ══════════════════════════════════════════════════════════════════════════════
# UNION-FIND  (internal helper for IncidentGrouper)
# ══════════════════════════════════════════════════════════════════════════════

class _UnionFind:
    """
    Path-compressed, rank-unioned disjoint-set structure.

    Clusters GUIDs that share any PAT ancestor into the same component,
    handling transitive membership automatically.
    """

    def __init__(self):
        self._parent: Dict[str, str] = {}
        self._rank:   Dict[str, int] = {}

    def find(self, x: str) -> str:
        """Return the root representative of x's set (with path compression)."""
        if x not in self._parent:
            self._parent[x] = x
            self._rank[x]   = 0
        if self._parent[x] != x:
            self._parent[x] = self.find(self._parent[x])
        return self._parent[x]

    def union(self, x: str, y: str) -> None:
        """Merge the sets containing x and y (union by rank)."""
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self._rank[rx] < self._rank[ry]:
            rx, ry = ry, rx
        self._parent[ry] = rx
        if self._rank[rx] == self._rank[ry]:
            self._rank[rx] += 1


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — INCIDENT GROUPER
# ══════════════════════════════════════════════════════════════════════════════

class IncidentGrouper:
    """
    Clusters actioned GUIDs into IncidentGroups by shared PAT ancestry.

    Algorithm
    ---------
    1. For each GUID, walk its PAT parent_guid chain upward.
    2. Union every (guid, ancestor) pair in the UnionFind.
    3. GUIDs that share ANY ancestor land in the same component.
    4. For each component, find the deepest common ancestor as root_guid.
    """

    def __init__(self, pat: PATBuilder, max_depth: int = 30):
        self._pat       = pat
        self._max_depth = max_depth

    def group(self, guids: List[str], logger: RemediationLogger) -> List[IncidentGroup]:
        """
        Cluster guids into IncidentGroups and log every chain + cluster result.

        Parameters
        ----------
        guids  : list of actioned GUIDs from IncidentCollector.
        logger : shared RemediationLogger.

        Returns
        -------
        List of IncidentGroup objects.
        """
        if not guids:
            logger.info("No GUIDs to group.")
            return []

        uf = _UnionFind()

        # Walk the PAT parent chain for every GUID and log each chain
        ancestry_map: Dict[str, List[str]] = {}
        logger.info("Walking PAT parent chains for each actioned GUID ...")

        for guid in guids:
            chain = self._pat.get_parent_chain(guid, max_depth=self._max_depth)
            ancestry_map[guid] = chain
            # Log the full chain so you can trace exactly which ancestors
            # caused two GUIDs to be merged into the same cluster
            logger.data(
                f"PAT parent chain for GUID={guid[:20]}",
                chain,
            )
            for ancestor in chain:
                uf.union(guid, ancestor)

        # Group by UnionFind representative
        clusters: Dict[str, List[str]] = defaultdict(list)
        for guid in guids:
            rep = uf.find(guid)
            clusters[rep].append(guid)

        logger.info(
            f"Union-find complete: {len(guids)} GUID(s) → {len(clusters)} cluster(s)."
        )

        # Build IncidentGroup per cluster and log the result
        groups = []
        for rep, members in clusters.items():
            root_guid = self._find_common_root(members, ancestry_map)
            grp       = IncidentGroup(root_guid=root_guid, member_guids=members)
            groups.append(grp)

            logger.data(
                f"Cluster → incident_id={grp.incident_id[:8]}",
                {
                    "incident_id":  grp.incident_id,
                    "root_guid":    root_guid,
                    "member_count": len(members),
                    "member_guids": members,
                },
            )

        return groups

    def _find_common_root(
        self,
        members:      List[str],
        ancestry_map: Dict[str, List[str]],
    ) -> str:
        """
        Return the deepest common ancestor across all members.
        Falls back to the root of the longest chain if no intersection exists.
        """
        if len(members) == 1:
            chain = ancestry_map.get(members[0], [members[0]])
            return chain[0] if chain else members[0]

        chains   = [ancestry_map.get(m, [m]) for m in members]
        set_list = [set(c) for c in chains]
        common   = set.intersection(*set_list)

        if not common:
            longest = max(chains, key=len)
            return longest[0] if longest else members[0]

        reference_chain = chains[0]
        for node in reference_chain:
            if node in common:
                return node

        return members[0]


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — LINEAGE BUILDER
# ══════════════════════════════════════════════════════════════════════════════

class LineageBuilder:
    """
    Fetches the full forensic lineage for an IncidentGroup from the PAT.

    Calls pat.build_remediation_context(root_guid) which implements:
      - upward ancestry walk (root → flagged node)
      - downward BFS blast radius (flagged node + all descendants)
      - injection victim discovery
      - chain_truncated flag
    """

    def __init__(self, pat: PATBuilder):
        self._pat = pat

    def build(self, group: IncidentGroup, logger: RemediationLogger) -> IncidentLineage:
        """
        Build IncidentLineage for one group and log the full process tree.

        Parameters
        ----------
        group  : the IncidentGroup to expand.
        logger : shared RemediationLogger.

        Returns
        -------
        IncidentLineage.
        """
        logger.info(
            f"Calling pat.build_remediation_context(root_guid={group.root_guid}) ..."
        )

        ctx = self._pat.build_remediation_context(
            flagged_guid=group.root_guid,
            max_depth=30,
        )

        lineage = IncidentLineage(
            group=             group,
            ancestry_chain=    ctx.get("ancestry_chain",    []),
            blast_radius=      ctx.get("blast_radius",      []),
            injection_victims= ctx.get("injection_victims", []),
            chain_truncated=   ctx.get("chain_truncated",   False),
        )

        # Log the full ASCII process tree + blast radius + victims so you can
        # visually verify the scope of the incident at a glance
        logger.lineage_summary(
            ancestry_chain=    lineage.ancestry_chain,
            blast_radius=      lineage.blast_radius,
            injection_victims= lineage.injection_victims,
            chain_truncated=   lineage.chain_truncated,
        )

        return lineage


# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — CONTEXT BUILDER
# ══════════════════════════════════════════════════════════════════════════════

class ContextBuilder:
    """
    Assembles the JSON payload that the RemediationAgent receives.

    Sources
    -------
    - Memgraph : pending_action, action_reason, action_stamped_at per node.
    - PAT      : full action stream per blast-radius process.
    - Lineage  : ancestry chain + blast radius node records.
    - NEW: analyst_file_actions    — File nodes stamped by analyst.
    - NEW: analyst_network_actions — Network/DNS nodes stamped by analyst.
    """

    # PAT action types surfaced as "notable" (first occurrence per type)
    _NOTABLE_TYPES = {
        "file_created", "file_deleted", "file_timestomped", "wrote_ads",
        "network_connection", "dns_query",
        "registry_write",
        "injected_thread_into", "received_injected_thread",
        "driver_loaded",
        "tampered_process", "was_tampered_by",
        "accessed_process_memory",
        "child_spawned",
    }

    def __init__(self, pat: PATBuilder, db: Memgraph):
        self._pat = pat
        self._db  = db

    def build_context(
        self,
        lineage:                 IncidentLineage,
        analyst_file_actions:    List[Dict[str, Any]],
        analyst_network_actions: List[Dict[str, Any]],
        logger:                  RemediationLogger,
    ) -> Dict[str, Any]:
        """
        Assemble and log the full LLM context payload.

        Parameters
        ----------
        lineage                 : IncidentLineage from LineageBuilder.
        analyst_file_actions    : all File nodes stamped by analyst (global).
        analyst_network_actions : all Network/DNS nodes stamped by analyst (global).
        logger                  : shared RemediationLogger.

        Returns
        -------
        JSON-serialisable dict.
        """
        group = lineage.group

        # Build the set of blast-radius GUIDs for scoping
        blast_radius_guids = {
            node.get("guid", "")
            for node in lineage.blast_radius
            if node.get("guid")
        }

        logger.info("Fetching analyst reasoning from Memgraph ...")
        analyst_reasoning = self._fetch_analyst_reasoning(group.member_guids, logger)

        # Scope file actions to this incident's blast radius
        logger.info("Scoping analyst file actions to this incident's blast radius ...")
        scoped_file_actions = self._scope_file_actions(
            analyst_file_actions, blast_radius_guids, logger
        )

        # Scope network actions to this incident's blast radius via PAT reverse index
        logger.info("Scoping analyst network actions to this incident's blast radius ...")
        scoped_network_actions = self._scope_network_actions(
            analyst_network_actions, blast_radius_guids, logger
        )

        logger.info("Building executed-actions list ...")
        executed_actions = self._build_executed_actions(
            analyst_reasoning, scoped_file_actions, scoped_network_actions, logger
        )

        logger.info("Building per-process action summaries from PAT ...")
        process_action_summaries = self._build_action_summaries(
            lineage.blast_radius, logger
        )

        payload = {
            "incident_id":              group.incident_id,
            "root_guid":                group.root_guid,
            "member_guids":             group.member_guids,
            "chain_truncated":          lineage.chain_truncated,
            "analyst_reasoning":        analyst_reasoning,
            "executed_actions":         executed_actions,
            # NEW: analyst-actioned artifacts scoped to this incident
            "analyst_file_actions":     scoped_file_actions,
            "analyst_network_actions":  scoped_network_actions,
            "lineage": {
                "ancestry_chain": lineage.ancestry_chain,
                "blast_radius":   lineage.blast_radius,
            },
            "process_action_summaries": process_action_summaries,
            "injection_victims":        lineage.injection_victims,
        }

        # Log the full payload (raw per-node action streams stripped for brevity;
        # those are fully visible in the tool-call log inside the agent section)
        logger.context_payload(payload)
        return payload

    # ── Scoping helpers ───────────────────────────────────────────────────────

    def _scope_file_actions(
        self,
        all_file_actions:    List[Dict[str, Any]],
        blast_radius_guids:  set,
        logger:              RemediationLogger,
    ) -> List[Dict[str, Any]]:
        """
        Filter analyst file actions to only those belonging to this incident.

        Primary filter : source_process_guid is in blast_radius_guids.
        Fallback filter: use PAT reverse index find_guids_by_file() to check
                         if any process that touched the file is in the blast
                         radius (covers files added by static rules with no
                         direct CREATED relationship in Memgraph).
        """
        scoped = []
        for entry in all_file_actions:
            path        = entry.get("path", "")
            source_guid = entry.get("source_process_guid", "")

            # Primary: direct relationship in Memgraph
            if source_guid and source_guid in blast_radius_guids:
                scoped.append(entry)
                continue

            # Fallback: PAT reverse index
            try:
                touching_guids = set(self._pat.find_guids_by_file(path))
                if touching_guids & blast_radius_guids:
                    scoped.append(entry)
            except Exception:
                pass  # PAT unavailable for this path — skip silently

        logger.info(
            f"File action scoping: {len(all_file_actions)} global → "
            f"{len(scoped)} scoped to this incident."
        )
        if scoped:
            logger.data("Scoped analyst file actions", scoped)

        return scoped

    def _scope_network_actions(
        self,
        all_network_actions: List[Dict[str, Any]],
        blast_radius_guids:  set,
        logger:              RemediationLogger,
    ) -> List[Dict[str, Any]]:
        """
        Filter analyst network/DNS actions to only those belonging to this incident.

        Uses PAT reverse indices:
          find_guids_by_ip(ip)       for ioc_type == "ip"
          find_guids_by_domain(dom)  for ioc_type == "domain"
        """
        scoped = []
        for entry in all_network_actions:
            value    = entry.get("value", "")
            ioc_type = entry.get("ioc_type", "")

            try:
                if ioc_type == "ip":
                    touching_guids = set(self._pat.find_guids_by_ip(value))
                elif ioc_type == "domain":
                    touching_guids = set(self._pat.find_guids_by_domain(value))
                else:
                    continue

                if touching_guids & blast_radius_guids:
                    scoped.append(entry)
            except Exception:
                pass

        logger.info(
            f"Network action scoping: {len(all_network_actions)} global → "
            f"{len(scoped)} scoped to this incident."
        )
        if scoped:
            logger.data("Scoped analyst network/DNS actions", scoped)

        return scoped

    # ── Analyst reasoning ─────────────────────────────────────────────────────

    def _fetch_analyst_reasoning(
        self,
        guids:  List[str],
        logger: RemediationLogger,
    ) -> List[Dict[str, Any]]:
        """Query Memgraph for the analyst agent's pending_action + reason per GUID."""
        if not guids:
            return []
        try:
            rows = list(self._db.execute_and_fetch(
                """
                UNWIND $guids AS guid
                MATCH (p:ProcessInstance {id: guid})
                WHERE p.pending_action IS NOT NULL
                RETURN
                    p.id                AS guid,
                    p.pending_action    AS pending_action,
                    p.action_reason     AS action_reason,
                    p.action_stamped_at AS action_stamped_at,
                    p.pid               AS pid,
                    p.score             AS score,
                    p.alive             AS alive
                """,
                {"guids": guids},
            ))
        except Exception as exc:
            logger.error("Memgraph analyst-reasoning fetch failed", exc)
            return []

        result = [
            {
                "guid":              row.get("guid", ""),
                "pending_action":    row.get("pending_action", ""),
                "action_reason":     row.get("action_reason", ""),
                "action_stamped_at": row.get("action_stamped_at", ""),
                "pid":               row.get("pid", ""),
                "score":             row.get("score", 0),
                "alive":             row.get("alive", True),
            }
            for row in rows if row.get("guid")
        ]

        logger.data("Analyst reasoning entries", result)
        return result

    # ── Executed actions (FIXED) ──────────────────────────────────────────────

    def _build_executed_actions(
        self,
        analyst_reasoning:       List[Dict[str, Any]],
        scoped_file_actions:     List[Dict[str, Any]],
        scoped_network_actions:  List[Dict[str, Any]],
        logger:                  RemediationLogger,
    ) -> List[Dict[str, Any]]:
        """
        Build the executed_actions list that the LLM sees under
        "EXECUTED ACTIONS (containment already performed)".

        This is FIXED vs the old _simulate_executed_actions:
          - Process actions: target_type=guid, target_value=process GUID  (correct)
          - File actions:    target_type=file, target_value=file path      (FIXED)
          - Network actions: target_type=ip,   target_value=IP address     (FIXED)
          - DNS actions:     target_type=domain, target_value=domain name  (FIXED)

        All entries are still marked status="simulated_done" until the Response
        Module is complete and action_executed can be queried instead.
        """
        executed = []

        # Process-level actions (from analyst_reasoning)
        for entry in analyst_reasoning:
            action = entry.get("pending_action", "")
            if not action:
                continue
            executed.append({
                "action":       action,
                "target_type":  "guid",
                "target_value": entry.get("guid", ""),
                "status":       "simulated_done",
                "executed_at":  entry.get("action_stamped_at", ""),
                "reason":       entry.get("action_reason", ""),
            })

        # File actions — target_value is the REAL file path
        for entry in scoped_file_actions:
            executed.append({
                "action":       entry.get("action_type", ""),
                "target_type":  "file",
                "target_value": entry.get("path", ""),      # FIXED: actual path
                "status":       "simulated_done",
                "executed_at":  entry.get("action_stamped_at", ""),
                "reason":       entry.get("action_reason", ""),
            })

        # Network / DNS actions — target_value is the REAL IP or domain
        for entry in scoped_network_actions:
            ioc_type = entry.get("ioc_type", "ip")
            executed.append({
                "action":       entry.get("action_type", ""),
                "target_type":  ioc_type,
                "target_value": entry.get("value", ""),     # FIXED: actual IP/domain
                "status":       "simulated_done",
                "executed_at":  entry.get("action_stamped_at", ""),
                "reason":       entry.get("action_reason", ""),
            })

        logger.data(
            "Executed actions (simulated — Response Module not yet complete)",
            executed,
        )
        return executed

    # ── Process action summaries ──────────────────────────────────────────────

    def _build_action_summaries(
        self,
        blast_radius: List[Dict[str, Any]],
        logger:       RemediationLogger,
    ) -> List[Dict[str, Any]]:
        """
        For every blast-radius node, summarise its PAT action stream and log it.
        """
        summaries = []

        for node in blast_radius:
            guid    = node.get("guid", "")
            image   = node.get("image", "?")
            actions = node.get("actions", [])

            counts:        Dict[str, int]            = defaultdict(int)
            first_notable: Dict[str, Dict[str, Any]] = {}

            for action in actions:
                atype = action.get("type", "unknown")
                counts[atype] += 1
                if atype in self._NOTABLE_TYPES and atype not in first_notable:
                    first_notable[atype] = self._extract_notable_fields(atype, action)

            summary = {
                "guid":            guid,
                "image":           image,
                "total_actions":   len(actions),
                "action_counts":   dict(counts),
                "notable_actions": [
                    {"type": atype, **fields}
                    for atype, fields in first_notable.items()
                ],
            }
            summaries.append(summary)

            logger.data(
                f"Action summary for {image} (GUID={guid[:20]})",
                {
                    "total_actions":   summary["total_actions"],
                    "action_counts":   summary["action_counts"],
                    "notable_actions": summary["notable_actions"],
                },
            )

        return summaries

    def _extract_notable_fields(
        self, action_type: str, action: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract the most relevant fields for a given PAT action type."""
        ts = action.get("ts", "")
        if action_type in ("file_created", "file_deleted", "file_timestomped"):
            return {"path": action.get("path", ""), "sha256": action.get("sha256", ""), "ts": ts}
        if action_type == "wrote_ads":
            return {"path": action.get("path", ""), "stream_name": action.get("stream_name", ""), "ts": ts}
        if action_type == "network_connection":
            return {"dst_ip": action.get("dst_ip", ""), "dst_port": action.get("dst_port", ""),
                    "dst_host": action.get("dst_host", ""), "protocol": action.get("protocol", ""), "ts": ts}
        if action_type == "dns_query":
            return {"query": action.get("query", ""), "results": action.get("results", ""), "ts": ts}
        if action_type == "registry_write":
            return {"key": action.get("key", ""), "details": action.get("details", ""),
                    "reg_type": action.get("reg_type", ""), "ts": ts}
        if action_type in ("injected_thread_into", "received_injected_thread"):
            return {"target_guid": action.get("target_guid", ""), "source_guid": action.get("source_guid", ""),
                    "target_image": action.get("target_image", ""), "source_image": action.get("source_image", ""), "ts": ts}
        if action_type in ("driver_loaded", "image_loaded"):
            return {"image_loaded": action.get("image_loaded", ""), "signed": action.get("signed", ""), "ts": ts}
        if action_type in ("tampered_process", "was_tampered_by"):
            return {"target_guid": action.get("target_guid", ""), "source_guid": action.get("source_guid", ""),
                    "tamper_type": action.get("tamper_type", ""), "ts": ts}
        if action_type == "accessed_process_memory":
            return {"target_guid": action.get("target_guid", ""), "target_image": action.get("target_image", ""),
                    "access_mask": action.get("access_mask", ""), "ts": ts}
        if action_type == "child_spawned":
            return {"child_guid": action.get("child_guid", ""), "child_image": action.get("child_image", ""),
                    "child_cmdline": action.get("child_cmdline", ""), "ts": ts}
        return {"ts": ts}


# ══════════════════════════════════════════════════════════════════════════════
# TOP-LEVEL ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def run_remediation(
    pat:           PATBuilder,
    db:            Optional[Memgraph] = None,
    grace_seconds: int = GRACE_PERIOD_SECONDS,
) -> List[RemediationReport]:
    """
    Main entry point called from agent.py after log replay finishes.

    Creates a RemediationLogger (opens the .log file), sleeps grace_seconds,
    then runs steps 1-5 for every incident group found.

    Parameters
    ----------
    pat           : the global PATBuilder instance from agent.py.
    db            : optional Memgraph instance. Opens one automatically if None.
    grace_seconds : seconds to wait before starting (default 60).

    Returns
    -------
    List of RemediationReport objects. Empty list on early failure.
    """
    logger = RemediationLogger()

    logger.phase("REMEDIATION PIPELINE STARTED")
    logger.info(
        f"Grace period = {grace_seconds}s — "
        "waiting for AnalystAgent to finish its last tick ..."
    )

    # ── Grace period ──────────────────────────────────────────────────────────
    remaining = grace_seconds
    while remaining > 0:
        chunk = min(5, remaining)
        time.sleep(chunk)
        remaining -= chunk
        logger.info(f"Grace period: {remaining}s remaining ...")

    logger.phase("GRACE PERIOD COMPLETE — STARTING PIPELINE")

    # ── Memgraph connection ───────────────────────────────────────────────────
    if db is None:
        try:
            db = Memgraph(host=MEMGRAPH_HOST, port=MEMGRAPH_PORT)
            logger.info(
                f"Connected to Memgraph at {MEMGRAPH_HOST}:{MEMGRAPH_PORT}"
            )
        except Exception as exc:
            logger.error("Cannot connect to Memgraph — aborting remediation", exc)
            logger.close()
            return []

    reports: List[RemediationReport] = []

    try:
        # ── STEP 1 ────────────────────────────────────────────────────────────
        logger.step(1, "INCIDENT COLLECTION",
                    "Query Memgraph for ProcessInstance nodes with "
                    "pending_action IS NOT NULL, plus File/Network/DNS nodes.")

        guids = IncidentCollector.get_actioned_guids(db, logger)

        # NEW: collect all analyst-actioned file and network artifacts globally.
        # These will be scoped per-incident in ContextBuilder.
        analyst_file_actions    = IncidentCollector.get_analyst_file_actions(db, logger)
        analyst_network_actions = IncidentCollector.get_analyst_network_actions(db, logger)

        if not guids:
            logger.info("No actioned GUIDs found — nothing to remediate.")
            logger.pipeline_complete(0)
            logger.close()
            return []

        # ── STEP 2 ────────────────────────────────────────────────────────────
        logger.step(2, "INCIDENT GROUPING",
                    "Walk PAT parent chains and union-find cluster GUIDs "
                    "that share any common ancestor.")
        grouper = IncidentGrouper(pat)
        groups  = grouper.group(guids, logger)
        logger.info(
            f"Clustering result: {len(guids)} GUID(s) → "
            f"{len(groups)} incident group(s)."
        )

        # ── Per-group pipeline (steps 3-5) ────────────────────────────────────
        lineage_builder = LineageBuilder(pat)
        context_builder = ContextBuilder(pat, db)

        for i, group in enumerate(groups, 1):
            logger.group_header(
                index=      i,
                total=      len(groups),
                incident_id=group.incident_id,
                root_guid=  group.root_guid,
                members=    group.member_guids,
            )

            try:
                # STEP 3
                logger.step(3, "LINEAGE BUILD",
                            f"Fetch ancestry + blast radius from PAT "
                            f"(root_guid={group.root_guid[:20]})")
                lineage = lineage_builder.build(group, logger)

                # STEP 4
                logger.step(4, "CONTEXT BUILD",
                            "Assemble LLM payload: analyst reasoning, "
                            "executed actions, file/network analyst actions, "
                            "lineage, process action summaries.")
                context_payload = context_builder.build_context(
                    lineage=                 lineage,
                    analyst_file_actions=    analyst_file_actions,
                    analyst_network_actions= analyst_network_actions,
                    logger=                  logger,
                )

                # Build per-incident dicts for the tool registry
                # so tools can annotate results inline.
                blast_guids = {
                    node.get("guid", "")
                    for node in lineage.blast_radius
                    if node.get("guid")
                }
                actioned_files_dict: Dict[str, str] = {}
                for entry in context_payload.get("analyst_file_actions", []):
                    path = entry.get("path", "")
                    if path:
                        actioned_files_dict[path.lower()] = entry.get("action_type", "")

                actioned_network_dict: Dict[str, str] = {}
                for entry in context_payload.get("analyst_network_actions", []):
                    value = entry.get("value", "")
                    if value:
                        actioned_network_dict[value.lower()] = entry.get("action_type", "")

                # STEP 5
                logger.step(5, "REMEDIATION AGENT",
                            "Run ReAct tool-calling loop → produce RemediationReport.")
                tool_registry = RemediationToolRegistry(
                    pat,
                    analyst_actioned_files=   actioned_files_dict,
                    analyst_actioned_network= actioned_network_dict,
                )
                agent  = RemediationAgent(tool_registry, logger)
                report = agent.run(
                    context_payload=context_payload,
                    incident_id=    group.incident_id,
                    root_guid=      group.root_guid,
                )

                reports.append(report)
                logger.report_summary(report)

            except Exception as exc:
                logger.error(
                    f"Group {group.incident_id[:8]} failed — skipping.", exc
                )
                continue

    except Exception as exc:
        logger.error("Fatal pipeline error", exc)

    finally:
        _save_summary(reports, logger)
        logger.pipeline_complete(len(reports))
        logger.close()

    return reports


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _save_summary(reports: List[RemediationReport], logger: RemediationLogger) -> None:
    """Write remediation_reports/remediation_summary.json with all reports combined."""
    import os
    import dataclasses
    try:
        os.makedirs("remediation_reports", exist_ok=True)
        path    = "remediation_reports/remediation_summary.json"
        payload = {
            "produced_at":     datetime.now(timezone.utc).isoformat(),
            "total_incidents": len(reports),
            "reports":         [dataclasses.asdict(r) for r in reports],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
        logger.info(f"Summary JSON saved → {path}")
    except Exception as exc:
        logger.error("Could not save remediation summary JSON", exc)