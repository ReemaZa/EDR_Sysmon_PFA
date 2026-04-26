"""
graph_extractor.py  —  Pulls a bounded SubgraphContext from Memgraph.

Given an anchor ProcessInstance GUID (the one that triggered investigation),
this module runs several focused Cypher queries to build a complete, self-
contained SubgraphContext that the analyst can reason about without any
further database access.

WHAT IS EXTRACTED (in order):
    1. Process tree   — CHILD_OF ancestors (up) and descendants (down), max 10 hops
    2. Template data  — INSTANCE_OF → ProcessTemplate, merged onto each InstanceNode
    3. Behaviour edges— all non-structural edges from every tree node
    4. Lateral nodes  — ProcessInstances reached via INJECTED_THREAD | ACCESSED_MEMORY
                        that have score > 0 (one hop only, no recursive expansion)
    5. Artefact nodes — File, Network, Registry, DNS, Driver endpoints of edges
    6. Timeline       — edge first_seen + process start_time sorted chronologically
    7. Size limits    — enforce MAX_NODES / MAX_EDGES, drop lowest-value nodes first

QUERY STRATEGY:
    Individual DISTINCT queries per concern rather than one large path query.
    Memgraph multi-path expansion returns duplicate nodes; individual queries
    with explicit UNWIND + DISTINCT are predictable and debuggable.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from gqlalchemy import Memgraph

from src.detection.l4_llm_detection.l4_models import (
    ArtifactNode,
    BehaviourEdge,
    InstanceNode,
    SubgraphContext,
)

MAX_NODES = 120
MAX_EDGES = 200

BEHAVIOUR_REL_TYPES = {
    "CREATED", "CONNECTED", "LOADED_DRIVER", "LOADED_IMAGE",
    "INJECTED_THREAD", "ACCESSED_MEMORY", "CREATED_FILE",
    "MODIFIED_REGISTRY", "QUERIED_DNS", "DELETED",
    "TIMESTOMPED", "WROTE_ADS", "TAMPERED",
}

ARTIFACT_LABELS = {"File", "Network", "Registry", "DNS", "Driver"}


class GraphExtractor:

    def __init__(self, db: Memgraph):
        self.db = db

    # ── PUBLIC ────────────────────────────────────────────────────────────────

    def extract(self, anchor_guid: str) -> Optional[SubgraphContext]:
        """Build and return a SubgraphContext for anchor_guid, or None."""

        # 1. Process tree GUIDs
        tree_guids = self._collect_process_tree(anchor_guid)
        if not tree_guids:
            return None

        # 2. Instances + template data
        instances = self._fetch_instances(tree_guids)
        if not instances:
            return None

        # 3. Behaviour edges from tree nodes
        edges, artifact_ids = self._fetch_behaviour_edges(tree_guids)

        # 4. Lateral instances (injection / memory access targets with score > 0)
        lateral_guids = self._collect_lateral_instances(tree_guids) - tree_guids
        if lateral_guids:
            instances += self._fetch_instances(lateral_guids)
            lat_edges, lat_artifacts = self._fetch_behaviour_edges(lateral_guids)
            edges       += lat_edges
            artifact_ids |= lat_artifacts

        # 5. Artefact nodes
        artifacts = self._fetch_artifacts(artifact_ids)

        # 6. Timeline
        timeline = self._build_timeline(edges, instances)

        # 7. Size limits
        instances, artifacts, edges = self._enforce_limits(
            anchor_guid, instances, artifacts, edges
        )

        anchor_score   = next((i.score for i in instances if i.guid == anchor_guid), 0)
        has_ghosts     = any(i.ghost for i in instances if i.guid != anchor_guid)

        return SubgraphContext(
            anchor_guid       = anchor_guid,
            anchor_score      = anchor_score,
            instances         = instances,
            artifacts         = artifacts,
            edges             = edges,
            timeline          = timeline,
            has_ghost_parents = has_ghosts,
            total_nodes       = len(instances) + len(artifacts),
            total_edges       = len(edges),
        )

    # ── PROCESS TREE ──────────────────────────────────────────────────────────

    def _collect_process_tree(self, anchor_guid: str) -> Set[str]:
        guids: Set[str] = {anchor_guid}

        for query in [
            # ancestors
            """
            MATCH (anchor:ProcessInstance {id: $guid})
            MATCH path = (anc:ProcessInstance)-[:CHILD_OF*0..10]->(anchor)
            UNWIND nodes(path) AS n
            RETURN DISTINCT n.id AS guid
            """,
            # descendants
            """
            MATCH (anchor:ProcessInstance {id: $guid})
            MATCH path = (anchor)-[:CHILD_OF*0..10]->(desc:ProcessInstance)
            UNWIND nodes(path) AS n
            RETURN DISTINCT n.id AS guid
            """,
        ]:
            for row in self._fetch(query, {"guid": anchor_guid}):
                if row.get("guid"):
                    guids.add(row["guid"])

        return guids

    # ── INSTANCES + TEMPLATES ─────────────────────────────────────────────────

    def _fetch_instances(self, guids: Set[str]) -> List[InstanceNode]:
        if not guids:
            return []
        rows = self._fetch(
            """
            UNWIND $guids AS guid
            MATCH (p:ProcessInstance {id: guid})
            OPTIONAL MATCH (p)-[:INSTANCE_OF]->(t:ProcessTemplate)
            RETURN
                p.id           AS guid,
                p.score        AS score,
                p.ghost        AS ghost,
                p.alive        AS alive,
                p.start_time   AS start_time,
                p.end_time     AS end_time,
                t.image        AS image,
                t.parent_image AS parent_image,
                t.cmdline      AS cmdline,
                t.user         AS user,
                t.description  AS description
            """,
            {"guids": list(guids)},
        )
        return [
            InstanceNode(
                guid         = r["guid"],
                score        = int(r["score"] or 0),
                ghost        = bool(r["ghost"]),
                alive        = bool(r.get("alive", True)),
                start_time   = r.get("start_time"),
                end_time     = r.get("end_time"),
                image        = r.get("image"),
                parent_image = r.get("parent_image"),
                cmdline      = r.get("cmdline"),
                user         = r.get("user"),
                description  = r.get("description"),
            )
            for r in rows if r.get("guid")
        ]

    # ── BEHAVIOUR EDGES ───────────────────────────────────────────────────────

    def _fetch_behaviour_edges(
        self, guids: Set[str]
    ) -> tuple[List[BehaviourEdge], Set[str]]:
        if not guids:
            return [], set()

        rel_filter = "|".join(BEHAVIOUR_REL_TYPES)
        rows = self._fetch(
            f"""
            UNWIND $guids AS guid
            MATCH (src:ProcessInstance {{id: guid}})-[r:{rel_filter}]->(dst)
            RETURN
                src.id           AS src_id,
                dst.id           AS dst_id,
                labels(dst)[0]   AS dst_label,
                type(r)          AS rel_type,
                r.total_score    AS total_score,
                r.count          AS count,
                r.first_seen     AS first_seen,
                r.last_seen      AS last_seen,
                r.techniques     AS techniques,
                r.tactics        AS tactics,
                r.finding_ids    AS finding_ids,
                r.port           AS port,
                r.protocol       AS protocol,
                r.access_mask    AS access_mask,
                r.start_function AS start_function,
                r.stream_name    AS stream_name,
                r.event_type     AS event_type
            """,
            {"guids": list(guids)},
        )

        edges: List[BehaviourEdge] = []
        artifact_ids: Set[str]     = set()

        for r in rows:
            dst_id    = r.get("dst_id", "")
            dst_label = r.get("dst_label", "")
            if not dst_id:
                continue
            if dst_label in ARTIFACT_LABELS:
                artifact_ids.add(dst_id)

            extra: Dict[str, Any] = {
                k: r[k] for k in
                ("port", "protocol", "access_mask",
                 "start_function", "stream_name", "event_type")
                if r.get(k) is not None
            }

            edges.append(BehaviourEdge(
                src_id      = r["src_id"],
                dst_id      = dst_id,
                rel_type    = r["rel_type"],
                total_score = int(r.get("total_score") or 0),
                count       = int(r.get("count") or 1),
                first_seen  = r.get("first_seen", ""),
                last_seen   = r.get("last_seen",  ""),
                techniques  = r.get("techniques",  []) or [],
                tactics     = r.get("tactics",     []) or [],
                finding_ids = r.get("finding_ids", []) or [],
                extra       = extra,
            ))

        return edges, artifact_ids

    # ── LATERAL INSTANCES ─────────────────────────────────────────────────────

    def _collect_lateral_instances(self, guids: Set[str]) -> Set[str]:
        if not guids:
            return set()
        rows = self._fetch(
            """
            UNWIND $guids AS guid
            MATCH (src:ProcessInstance {id: guid})
                  -[:INJECTED_THREAD|ACCESSED_MEMORY]->(tgt:ProcessInstance)
            WHERE tgt.score > 0
            RETURN DISTINCT tgt.id AS guid
            """,
            {"guids": list(guids)},
        )
        return {r["guid"] for r in rows if r.get("guid")}

    # ── ARTEFACT NODES ────────────────────────────────────────────────────────

    def _fetch_artifacts(self, artifact_ids: Set[str]) -> List[ArtifactNode]:
        if not artifact_ids:
            return []
        rows = self._fetch(
            """
            UNWIND $ids AS aid
            MATCH (n {id: aid})
            WHERE NOT n:ProcessInstance AND NOT n:ProcessTemplate
            RETURN n.id AS id, labels(n)[0] AS label, n.image AS image
            """,
            {"ids": list(artifact_ids)},
        )
        result = []
        for r in rows:
            extra = {"image": r["image"]} if r.get("image") else {}
            result.append(ArtifactNode(id=r["id"], label=r.get("label", "Unknown"), extra=extra))
        return result

    # ── TIMELINE ──────────────────────────────────────────────────────────────

    def _build_timeline(
        self,
        edges:     List[BehaviourEdge],
        instances: List[InstanceNode],
    ) -> List[Dict[str, str]]:
        events = []

        for inst in instances:
            if inst.start_time and not inst.ghost:
                events.append({
                    "timestamp":  inst.start_time,
                    "rel_type":   "PROCESS_START",
                    "src":        inst.image or inst.guid,
                    "dst":        "",
                    "techniques": "",
                })

        for edge in edges:
            if edge.first_seen:
                events.append({
                    "timestamp":  edge.first_seen,
                    "rel_type":   edge.rel_type,
                    "src":        edge.src_id,
                    "dst":        edge.dst_id,
                    "techniques": ", ".join(edge.techniques),
                })

        events.sort(key=lambda e: e["timestamp"])
        return events

    # ── SIZE ENFORCEMENT ──────────────────────────────────────────────────────

    def _enforce_limits(
        self,
        anchor_guid: str,
        instances:   List[InstanceNode],
        artifacts:   List[ArtifactNode],
        edges:       List[BehaviourEdge],
    ) -> tuple[List[InstanceNode], List[ArtifactNode], List[BehaviourEdge]]:

        total = len(instances) + len(artifacts)
        if total <= MAX_NODES and len(edges) <= MAX_EDGES:
            return instances, artifacts, edges

        # Drop artefacts first (alphabetical tiebreak)
        keep_artifacts = sorted(artifacts, key=lambda a: a.id)[
            : max(0, MAX_NODES - len(instances))
        ]

        total = len(instances) + len(keep_artifacts)
        if total > MAX_NODES:
            non_anchor = sorted(
                [i for i in instances if i.guid != anchor_guid],
                key=lambda i: -i.score,
            )[: MAX_NODES - len(keep_artifacts) - 1]
            anchor_list  = [i for i in instances if i.guid == anchor_guid]
            keep_instances = anchor_list + non_anchor
        else:
            keep_instances = instances

        valid_ids = {i.guid for i in keep_instances} | {a.id for a in keep_artifacts}
        keep_edges = [
            e for e in edges if e.src_id in valid_ids and e.dst_id in valid_ids
        ][:MAX_EDGES]

        return keep_instances, keep_artifacts, keep_edges

    # ── DB HELPER ─────────────────────────────────────────────────────────────

    def _fetch(self, query: str, params: dict) -> List[Dict]:
        try:
            return list(self.db.execute_and_fetch(query, params))
        except Exception as exc:
            print(f"[GraphExtractor][FAIL] {exc}")
            return []