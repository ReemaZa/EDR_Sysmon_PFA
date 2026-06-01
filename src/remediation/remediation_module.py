"""
remediation_module.py  —  Orchestrator: runs the full remediation pipeline.

PIPELINE (called once, after log ingestion is complete + 60s grace period)
──────────────────────────────────────────────────────────────────────────
  1. IncidentCollector  — read actioned_nodes.jsonl for stamped GUIDs,
                          File, Network, and DNS nodes
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
can stamp all pending_actions before we start.

DATA SOURCES
────────────
All data now comes from actioned_nodes.jsonl (written by ThreatAnalyst._append_actioned_nodes):
  - ProcessInstance GUIDs with pending_action
  - File nodes with pending_action
  - Network/DNS nodes with pending_action
  
No Memgraph queries are performed in the remediation pipeline.
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
from src.detection.l4_llm_detection.action_executor import ActionExecutor
GRACE_PERIOD_SECONDS = 60
MAX_BLAST_RADIUS_IN_PROMPT = 15  # Limit blast radius shown in LLM prompt to reduce tokens


# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — INCIDENT COLLECTOR
# ══════════════════════════════════════════════════════════════════════════════

class IncidentCollector:
    """
    Reads actioned_nodes.jsonl (written by ThreatAnalyst._append_actioned_nodes)
    for all nodes the AnalystAgent stamped with a pending_action:
      - ProcessInstance nodes  (target_type == "guid")
      - File nodes             (target_type == "file")
      - Network nodes          (target_type == "ip")
      - DNS nodes              (target_type == "domain")

    No Memgraph queries are performed here.
    """

    @staticmethod
    def _load_unhandled(logger: RemediationLogger) -> List[Dict[str, Any]]:
        """
        Load all entries from actioned_nodes.jsonl where
        remediation_handled == False.

        Returns the full list of such records (not deduplicated yet).
        """
        from src.detection.l4_llm_detection.threat_analyst import ACTIONED_NODES_FILE
        import os

        if not os.path.exists(ACTIONED_NODES_FILE):
            logger.info(
                f"{ACTIONED_NODES_FILE} does not exist — "
                "no actioned nodes recorded yet."
            )
            return []

        records = []
        try:
            with open(ACTIONED_NODES_FILE, "r", encoding="utf-8") as f:
                for lineno, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        if not rec.get("remediation_handled", False):
                            records.append(rec)
                    except json.JSONDecodeError as exc:
                        logger.info(
                            f"[IncidentCollector] Skipping malformed line "
                            f"{lineno} in {ACTIONED_NODES_FILE}: {exc}"
                        )
        except Exception as exc:
            logger.error(f"Could not read {ACTIONED_NODES_FILE}", exc)
            return []

        logger.info(
            f"Loaded {len(records)} unhandled record(s) "
            f"from {ACTIONED_NODES_FILE}."
        )
        return records

    @staticmethod
    def get_actioned_guids(db: Memgraph, logger: RemediationLogger) -> List[str]:
        """
        Return every ProcessInstance GUID that has a non-null pending_action.

        Reads from actioned_nodes.jsonl (target_type == "guid",
        remediation_handled == False).  Deduplicates by target_value, keeping
        the latest stamped_at entry.

        Parameters
        ----------
        db     : kept for API compatibility (unused).
        logger : shared RemediationLogger for this pipeline run.

        Returns
        -------
        List of GUID strings, deduplicated. Empty list if none found.
        """
        logger.info(
            "Reading actioned_nodes.jsonl for ProcessInstance GUIDs "
            "(target_type='guid', remediation_handled=False) ..."
        )

        records = IncidentCollector._load_unhandled(logger)

        # Filter to guid entries only
        guid_records = [
            r for r in records
            if r.get("target_type") == "guid" and r.get("target_value")
        ]

        # Deduplicate by target_value — keep the latest stamped_at
        latest: Dict[str, Dict[str, Any]] = {}
        for rec in guid_records:
            tv = rec["target_value"]
            existing = latest.get(tv)
            if existing is None or rec.get("stamped_at", "") > existing.get("stamped_at", ""):
                latest[tv] = rec

        guids = list(latest.keys())

        logger.info(f"Found {len(guids)} actioned GUID(s).")
        if latest:
            logger.data(
                "Actioned nodes returned from actioned_nodes.jsonl",
                [
                    {
                        "guid":        rec.get("target_value", ""),
                        "action_type": rec.get("action_type", ""),
                        "stamped_at":  rec.get("stamped_at", ""),
                    }
                    for rec in latest.values()
                ],
            )

        return guids

    @staticmethod
    def get_analyst_file_actions(
        db: Memgraph, logger: RemediationLogger
    ) -> List[Dict[str, Any]]:
        """
        Read File-level actions from actioned_nodes.jsonl.

        Filters: target_type == "file", remediation_handled == False.

        Returns
        -------
        List of dicts:
          {
            "path":                str,   # target_value (file path)
            "action_type":         str,
            "action_reason":       str,
            "action_stamped_at":   str,
            "source_process_guid": str,   # guid field from the record
          }
        """
        logger.info(
            "Reading actioned_nodes.jsonl for File actions "
            "(target_type='file', remediation_handled=False) ..."
        )

        records = IncidentCollector._load_unhandled(logger)

        # Deduplicate by target_value — keep the latest stamped_at entry,
        # same as get_actioned_guids. Without this, a file actioned across
        # multiple ticks produces one entry per tick, bloating the LLM prompt.
        latest: Dict[str, Any] = {}
        for rec in records:
            if rec.get("target_type") != "file" or not rec.get("target_value"):
                continue
            tv = rec["target_value"]
            existing = latest.get(tv)
            if existing is None or rec.get("stamped_at", "") > existing.get("stamped_at", ""):
                latest[tv] = rec

        result = [
            {
                "path":                rec.get("target_value", ""),
                "action_type":         rec.get("action_type", ""),
                "action_reason":       rec.get("reason", ""),
                "action_stamped_at":   rec.get("stamped_at", ""),
                "source_process_guid": rec.get("guid", ""),
            }
            for rec in latest.values()
        ]

        logger.info(f"Found {len(result)} analyst-actioned File record(s) (deduplicated).")
        if result:
            logger.data("Analyst-actioned File nodes", result)

        return result

    @staticmethod
    def get_analyst_network_actions(
        db: Memgraph, logger: RemediationLogger
    ) -> List[Dict[str, Any]]:
        """
        Read Network/DNS actions from actioned_nodes.jsonl.

        Filters: target_type in ("ip", "domain"), remediation_handled == False.

        Returns
        -------
        List of dicts:
          {
            "value":             str,   # IP address or domain name
            "action_type":       str,   # "ip_block" | "dns_block"
            "action_reason":     str,
            "action_stamped_at": str,
            "ioc_type":          str,   # "ip" | "domain"
          }
        """
        logger.info(
            "Reading actioned_nodes.jsonl for Network/DNS actions "
            "(target_type in ('ip','domain'), remediation_handled=False) ..."
        )

        records = IncidentCollector._load_unhandled(logger)

        # Deduplicate by target_value — keep the latest stamped_at entry.
        latest: Dict[str, Any] = {}
        for rec in records:
            if rec.get("target_type") not in ("ip", "domain") or not rec.get("target_value"):
                continue
            tv = rec["target_value"]
            existing = latest.get(tv)
            if existing is None or rec.get("stamped_at", "") > existing.get("stamped_at", ""):
                latest[tv] = rec

        result = [
            {
                "value":             rec.get("target_value", ""),
                "action_type":       rec.get("action_type", ""),
                "action_reason":     rec.get("reason", ""),
                "action_stamped_at": rec.get("stamped_at", ""),
                "ioc_type":          rec.get("target_type", ""),  # "ip" or "domain"
            }
            for rec in latest.values()
        ]

        logger.info(f"Found {len(result)} analyst-actioned Network/DNS record(s) (deduplicated).")
        if result:
            logger.data("Analyst-actioned Network/DNS nodes", result)

        return result

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
    - actioned_nodes.jsonl : analyst pending_action, action_reason, stamped_at
    - PAT                  : full action stream per blast-radius process.
    - Lineage              : ancestry chain + blast radius node records.
    - analyst_file_actions    — File nodes stamped by analyst.
    - analyst_network_actions — Network/DNS nodes stamped by analyst.
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

    def __init__(self, pat: PATBuilder):
        self._pat = pat

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
        # Pass empty lists for file/network — those are already present in
        # analyst_file_actions and analyst_network_actions in the payload.
        # Passing them again into executed_actions would duplicate the data
        # and inflate the LLM prompt unnecessarily.
        executed_actions = self._build_executed_actions(
            analyst_reasoning, [], [], logger
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
        """
        Read analyst reasoning from actioned_nodes.jsonl for the given GUIDs.
        
        Filters: target_type == "guid", remediation_handled == False.
        Only returns entries where pending_action IS NOT NULL.
        """
        if not guids:
            return []
        
        records = IncidentCollector._load_unhandled(logger)
        guid_set = set(guids)
        
        result = []
        for rec in records:
            if (rec.get("target_type") == "guid" and 
                rec.get("target_value") in guid_set and
                rec.get("action_type")):  # action_type holds the pending_action
                
                result.append({
                    "guid":              rec.get("target_value", ""),
                    "pending_action":    rec.get("action_type", ""),
                    "action_reason":     rec.get("reason", ""),
                    "action_stamped_at": rec.get("stamped_at", ""),
                    "pid":               rec.get("pid", ""),
                    "score":             rec.get("score", 0),
                    "alive":             rec.get("alive", True),
                })
        
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
        
        OPTIMISED: Limit notable actions to the 3 most relevant types to reduce
        token usage and comply with API rate limits. Only show actions that are
        most likely to reveal persistence, exfiltration, or backdoors.
        """
        summaries = []
        
        # Priority order: which action types are most forensically significant?
        PRIORITY_ACTIONS = [
            "registry_write",  # persistence indicators
            "file_created",    # dropped files, persistence droppers
            "network_connection",  # exfiltration, C2
            "injected_thread_into",  # backdoors
            "driver_loaded",   # rootkit indicators
            "child_spawned",   # lateral movement, command execution
        ]

        for node in blast_radius:
            guid    = node.get("guid", "")
            image   = node.get("image", "?")
            actions = node.get("actions", [])

            counts:        Dict[str, int]            = defaultdict(int)
            first_notable: Dict[str, Dict[str, Any]] = {}

            # First pass: count all actions and find first of each notable type
            for action in actions:
                atype = action.get("type", "unknown")
                counts[atype] += 1
                if atype in self._NOTABLE_TYPES and atype not in first_notable:
                    first_notable[atype] = self._extract_notable_fields(atype, action)

            # Second pass: prioritize which notable actions to include
            # Keep only the top 3 most important types to reduce token usage
            prioritized_notable = {}
            for priority_type in PRIORITY_ACTIONS:
                if priority_type in first_notable:
                    prioritized_notable[priority_type] = first_notable[priority_type]
                if len(prioritized_notable) >= 3:  # Limit to 3 to save tokens
                    break

            summary = {
                "guid":            guid,
                "image":           image,
                "total_actions":   len(actions),
                "action_counts":   dict(counts),
                "notable_actions": [
                    {"type": atype, **fields}
                    for atype, fields in prioritized_notable.items()
                ],
            }
            summaries.append(summary)

            logger.data(
                f"Action summary for {image} (GUID={guid[:20]})",
                {
                    "total_actions":   summary["total_actions"],
                    "action_counts":   summary["action_counts"],
                    "notable_actions_shown": len(summary["notable_actions"]),
                    "notable_actions_total": len(first_notable),
                },
            )

        return summaries

    def _extract_notable_fields(
        self, action_type: str, action: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract the most relevant fields for a given PAT action type.
        
        Truncates only -EncodedCommand values in cmdlines to reduce token usage.
        All other strings (file paths, etc.) are kept intact.
        """
        ts = action.get("ts", "")
        
        def truncate_encoded_command(cmdline: str) -> str:
            """
            Find '-EncodedCommand' in cmdline and truncate everything after it
            to just a few characters (e.g., 'TRUNCATED').
            
            Example:
                Input:  'powershell.exe -EncodedCommand JgBGQBwAHAAZQByAA=='
                Output: 'powershell.exe -EncodedCommand TRUNCATED'
            """
            if not isinstance(cmdline, str):
                return cmdline
            
            lower_cmd = cmdline.lower()
            if "encodedcommand" not in lower_cmd:
                return cmdline  # No encoded command, return as-is
            
            # Find the index of '-EncodedCommand' (case-insensitive)
            idx = lower_cmd.find("encodedcommand")
            if idx == -1:
                return cmdline
            
            # Find where the encoded string starts (after '-EncodedCommand' and optional spaces)
            # Typically: '-EncodedCommand JkBG...'
            start = idx + len("encodedcommand")
            # Skip whitespace/hyphens
            while start < len(cmdline) and cmdline[start] in (' ', '\t', '-'):
                start += 1
            
            # Keep everything before the encoded value, replace encoded value with 'TRUNCATED'
            return cmdline[:start] + "TRUNCATED"
        
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
            child_cmdline = action.get("child_cmdline", "")
            # Truncate only if it contains -EncodedCommand
            child_cmdline = truncate_encoded_command(child_cmdline)
            return {"child_guid": action.get("child_guid", ""), "child_image": action.get("child_image", ""),
                    "child_cmdline": child_cmdline, "ts": ts}
        return {"ts": ts}


# ── ACTION TYPE MAPPING ───────────────────────────────────────────────────────
# RemediationAgent uses different field names / action type strings than
# AnalystAgent.  This adapter normalises a cleanup_action dict into the
# shape ActionExecutor._dispatch() expects.

_REMEDIATION_TO_ANALYST_TYPE: Dict[str, str] = {
    "quarantine_file":      "file_quarantine",
    "remove_registry_key":  "registry_delete",  # DELETE registry key instead of alerting
    "block_ip":             "ip_block",
    "block_domain":         "dns_block",
    "disable_service":      "alert",          # no direct RF call — raise alert
    "scan_process":         "alert",          # informational — raise alert
    "revoke_credential":    "identity_revocation",
    "patch_vulnerability":  "patching",
    "reimage_host":         "shutdown",       # closest available action
    "alert_analyst":        "alert",
}

def _transform_task_name_to_registry_path(target: str) -> str:
    """
    Convert a remediation agent task target (e.g., "Task: T1053_005_OnStartup")
    into a registry value deletion path that deletes ONLY the specific scheduled task,
    not the entire parent registry key.
    
    Windows Scheduled Tasks are stored in:
    - Task subkeys: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks
      (Each task is a subkey with GUID name)
    
    For deleting a task by name, use:
    - schtasks /delete /tn "TaskName" /f
    
    However, if we need registry-level deletion, we delete the task's subkey:
    - Format: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\{GUID}
    
    Since the remediation report only provides the task NAME, we construct a command
    that will be converted to schtasks deletion instead of direct registry deletion.
    
    For now, return a special format: "schtasks://{task_name}" which indicates
    that ActionExecutor should handle this via schtasks command rather than registry.
    """
    # Extract task name from formats like:
    # - "Task: T1053_005_OnStartup"
    # - "T1053_005_OnStartup"
    # - "Task:T1053_005_OnStartup"
    
    task_name = target
    if target.lower().startswith("task:"):
        task_name = target[5:].strip()
    elif target.lower().startswith("task "):
        task_name = target[5:].strip()
    
    # Return format that indicates this should use schtasks deletion
    # Format: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Scheduler@schtasks:{task_name}
    # This tells registry_delete to use schtasks /delete instead
    return f"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Scheduler@schtasks:{task_name}"

def _remediation_action_to_executor_format(action: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Convert a RemediationAgent cleanup_action dict into the format
    ActionExecutor._dispatch() expects.

    RemediationAgent schema:
        { priority, action_type, target, reason, confidence, confidence_reason }

    ActionExecutor schema:
        { id, priority, type, target_type, target_value, reason }

    Returns None if the action_type has no RF equivalent (will be skipped).
    """
    import uuid

    action_type  = action.get("action_type", "")
    target       = action.get("target", "")
    priority     = action.get("priority", 5)
    reason       = action.get("reason", "")
    confidence   = action.get("confidence", 0.5)

    mapped_type = _REMEDIATION_TO_ANALYST_TYPE.get(action_type)
    if not mapped_type:
        return None  # unknown — skip

    # Infer target_type from the target string content
    if mapped_type == "ip_block":
        target_type = "ip"
    elif mapped_type == "dns_block":
        target_type = "domain"
    elif mapped_type in ("file_quarantine", "file_deletion"):
        target_type = "file"
    elif mapped_type == "registry_delete":
        target_type = "registry"
        # Transform task name to registry path for scheduled tasks
        # Example: "Task: T1053_005_OnStartup" → registry path to delete
        target = _transform_task_name_to_registry_path(target)
    elif mapped_type == "identity_revocation":
        target_type = "user"
    elif mapped_type in ("patching", "shutdown"):
        target_type = "host"
    else:
        target_type = "host"  # alert / generic

    return {
        "id":           f"rem-{uuid.uuid4().hex[:8]}",
        "priority":     priority,
        "type":         mapped_type,
        "target_type":  target_type,
        "target_value": target,
        "reason":       f"[Remediation|conf={confidence:.2f}] {reason}",
    }


def _transform_task_name_to_registry_path(target: str) -> str:
    """
    Transform a scheduled task name into a registry deletion path.
    
    Windows Scheduled Tasks are stored in the registry at:
      HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\<TaskName>
    
    Parameters
    ----------
    target : str
        Either a task name (e.g., "T1053_005_OnStartup") or 
        a prefixed description (e.g., "Task: T1053_005_OnStartup")
    
    Returns
    -------
    str
        Full registry path to delete, or the original target if it's already a path
    """
    # If it's already a registry path, return as-is
    if target.startswith("HKEY_") or target.startswith("HKLM\\") or target.startswith("HKU\\"):
        return target
    
    # Extract task name (remove "Task: " prefix if present)
    task_name = target.replace("Task: ", "").strip()
    
    # Build the registry path to the scheduled task
    # Note: Scheduled tasks are stored under TaskCache\Tree\
    registry_path = f"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\{task_name}"
    
    return registry_path

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
        context_builder = ContextBuilder(pat)
        
        # Rate limiting: delay between incident groups to avoid API rate limits
        # Google Gemini: 15 requests per minute = 1 request per 4 seconds
        # Using 5 seconds between incidents to stay well under the limit
        inter_incident_delay = 5 if len(groups) > 1 else 0  # seconds between incidents

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

                # ── Execute remediation cleanup_actions ───────────────────────
                # Mirror exactly what ThreatAnalyst does for analyst actions.
                if report.cleanup_actions:
                    executor_actions = []
                    for ca in report.cleanup_actions:
                        converted = _remediation_action_to_executor_format(ca)
                        if converted:
                            executor_actions.append(converted)
                        else:
                            logger.info(
                                f"[Remediation] Skipping unmapped action_type="
                                f"{ca.get('action_type')} target={ca.get('target', '')}"
                            )

                    if executor_actions:
                        logger.info(
                            f"[Remediation] Executing {len(executor_actions)} "
                            f"cleanup action(s) for incident {group.incident_id[:8]} ..."
                        )
                        # ActionExecutor is instantiated in automatic mode.
                        # If you want approval mode, pass mode="approval" and
                        # use the existing approval_response_executor flow.
                        action_executor = ActionExecutor(mode="automatic")
                        # execute_sync so we wait before moving to the next incident
                        results = action_executor.execute_sync(
                            executor_actions, group.root_guid
                        )
                        for r in results:
                            logger.info(
                                f"[Remediation][ACTION RESULT] "
                                f"{r.get('action')} → status={r.get('status')} "
                                f"target={r.get('target_value', '')}"
                            )

                    # ── Change 5: Write remediation cleanup_actions to ledger ──
                    _append_remediation_cleanup_actions(
                        report.cleanup_actions, group.root_guid, logger
                    )

                # ── Change 4: Mark handled entries in actioned_nodes.jsonl ────
                # Collect the exact target_values that were scoped to this group
                # so we mark only the right file/network entries.
                scoped_file_tv = [
                    e.get("path", "")
                    for e in context_payload.get("analyst_file_actions", [])
                    if e.get("path")
                ]
                scoped_net_tv = [
                    e.get("value", "")
                    for e in context_payload.get("analyst_network_actions", [])
                    if e.get("value")
                ]
                _mark_actioned_nodes_handled(
                    member_guids=   group.member_guids,
                    scoped_file_tv= scoped_file_tv,
                    scoped_net_tv=  scoped_net_tv,
                    logger=         logger,
                )
                
                # Rate limiting: add delay between incident groups to avoid 
                # hitting Google API per-minute rate limits
                if i < len(groups) and inter_incident_delay > 0:
                    logger.info(
                        f"Rate limit delay: waiting {inter_incident_delay}s "
                        f"before processing next incident group..."
                    )
                    time.sleep(inter_incident_delay)

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

def _mark_actioned_nodes_handled(
    member_guids:    List[str],
    scoped_file_tv:  List[str],
    scoped_net_tv:   List[str],
    logger:          RemediationLogger,
) -> None:
    """
    Mark entries in actioned_nodes.jsonl as remediation_handled=True for:
      - All entries whose target_value is in member_guids (GUID entries)
      - All file/network entries whose target_value is in scoped_file_tv or
        scoped_net_tv (the values scoped to this incident group).

    Uses a load-update-write strategy keyed by (action_type, target_value).
    If the same key appears multiple times, ALL matching lines are updated.
    """
    from src.detection.l4_llm_detection.threat_analyst import ACTIONED_NODES_FILE
    import os

    if not os.path.exists(ACTIONED_NODES_FILE):
        return

    member_set = set(member_guids)
    file_set   = set(scoped_file_tv)
    net_set    = set(scoped_net_tv)

    updated = 0
    lines_out = []
    try:
        with open(ACTIONED_NODES_FILE, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    lines_out.append(line)
                    continue
                try:
                    rec = json.loads(stripped)
                    tv  = rec.get("target_value", "")
                    tt  = rec.get("target_type", "")
                    if (
                        (tt == "guid"   and tv in member_set) or
                        (tt == "file"   and tv in file_set)   or
                        (tt in ("ip", "domain") and tv in net_set)
                    ):
                        rec["remediation_handled"] = True
                        updated += 1
                    lines_out.append(json.dumps(rec) + "\n")
                except json.JSONDecodeError:
                    lines_out.append(line)

        with open(ACTIONED_NODES_FILE, "w", encoding="utf-8") as f:
            f.writelines(lines_out)

        logger.info(
            f"[actioned_nodes] Marked {updated} record(s) as "
            f"remediation_handled=True."
        )
    except Exception as exc:
        logger.error(
            f"Could not update {ACTIONED_NODES_FILE} "
            f"(mark handled)", exc
        )


def _append_remediation_cleanup_actions(
    cleanup_actions: List[Dict[str, Any]],
    root_guid:       str,
    logger:          RemediationLogger,
) -> None:
    """
    Append each remediation cleanup_action to actioned_nodes.jsonl with
    source="remediation" and remediation_handled=True (already executed).

    This gives a complete ledger — analyst and remediation actions in one file.
    No graph writes needed for remediation actions.
    """
    from src.detection.l4_llm_detection.threat_analyst import ACTIONED_NODES_FILE

    if not cleanup_actions:
        return

    ts = datetime.now(timezone.utc).isoformat()
    records = []
    for ca in cleanup_actions:
        action_type  = ca.get("action_type", "unknown")
        target       = ca.get("target", "")
        if not target:
            continue
        # Infer target_type from action_type (mirrors _remediation_action_to_executor_format)
        if action_type == "block_ip":
            target_type = "ip"
        elif action_type == "block_domain":
            target_type = "domain"
        elif action_type in ("quarantine_file",):
            target_type = "file"
        elif action_type in ("remove_registry_key",):
            target_type = "registry"
        else:
            target_type = "host"

        records.append({
            "guid":                root_guid,
            "action_type":         action_type,
            "target_type":         target_type,
            "target_value":        target,
            "reason":              ca.get("reason", ""),
            "stamped_at":          ts,
            "remediation_handled": True,
            "source":              "remediation",
        })

    if not records:
        return

    try:
        with open(ACTIONED_NODES_FILE, "a", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")
        logger.info(
            f"[actioned_nodes] Appended {len(records)} remediation "
            f"cleanup_action record(s) (source=remediation, handled=True)."
        )
    except Exception as exc:
        logger.error(
            f"Could not append remediation cleanup_actions to "
            f"{ACTIONED_NODES_FILE}", exc
        )


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