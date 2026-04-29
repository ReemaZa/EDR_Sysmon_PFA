"""
graph_extractor.py  —  Pulls a bounded SubgraphContext from Memgraph.
Aligned to graph_builder.py v4.0 schema.

SCHEMA FACTS (from graph_builder):
    ProcessInstance  : id, score, ghost, alive, start_time, end_time
                       NO image/cmdline/user — those are on ProcessTemplate
    ProcessTemplate  : template_hash, image, parent_image, cmdline, user,
                       description, seen_count, total_score, first_seen, last_seen
    INSTANCE_OF      : ProcessInstance → ProcessTemplate
    CHILD_OF         : child ProcessInstance → parent ProcessInstance
                       created ONLY from Event-1
    CREATED          : parent ProcessInstance → child ProcessInstance (Event-1)
    INJECTED_THREAD  : src → tgt ProcessInstance (Event-8)
    ACCESSED_MEMORY  : src → tgt ProcessInstance (Event-10)
    TAMPERED         : attacker → victim ProcessInstance (Event-25)
    Artifact nodes   : File, Network, Registry, DNS, Driver
    Artifact edges   : TIMESTOMPED, CONNECTED, LOADED_DRIVER, LOADED_IMAGE,
                       CREATED_FILE, MODIFIED_REGISTRY, QUERIED_DNS,
                       DELETED, WROTE_ADS
    Edge properties  : edge_hash, first_seen, last_seen, count,
                       total_score, finding_ids, techniques, tactics
                       + extras per type

TRAVERSAL RULES:
    IN to_investigate:
        → include, fetch behavior
        → expand CHILD_OF ancestors + children (all, no score filter)
        → expand laterals (INJECTED_THREAD/ACCESSED_MEMORY/TAMPERED)
          only if target.score > 0
        → new to_investigate node found → reset hop budget to HOP_RESET
        → apply same rule recursively

    NOT in to_investigate (any score):
        → include, fetch behavior, STOP

    Lateral target score = 0 → ignore completely

TEMPLATE DEDUPLICATION:
    InstanceNode carries only template_hash.
    TemplateNodes stored once in SubgraphContext.templates dict.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from gqlalchemy import Memgraph

MAX_NODES   = 120
MAX_EDGES   = 200
HOP_INITIAL = 10
HOP_RESET   = 10

BEHAVIOUR_REL_TYPES = {
    "CREATED",
    "CONNECTED",
    "LOADED_DRIVER",
    "LOADED_IMAGE",
    "INJECTED_THREAD",
    "ACCESSED_MEMORY",
    "CREATED_FILE",
    "MODIFIED_REGISTRY",
    "QUERIED_DNS",
    "DELETED",
    "TIMESTOMPED",
    "WROTE_ADS",
    "TAMPERED",
}

LATERAL_REL_TYPES = {"INJECTED_THREAD", "ACCESSED_MEMORY", "TAMPERED"}
ARTIFACT_LABELS   = {"File", "Network", "Registry", "DNS", "Driver","Image"}


# ── data models ───────────────────────────────────────────────────────────────

@dataclass
class TemplateNode:
    template_hash: str
    image:         Optional[str] = None
    parent_image:  Optional[str] = None
    cmdline:       Optional[str] = None
    user:          Optional[str] = None
    description:   Optional[str] = None
    seen_count:    int           = 0
    total_score:   int           = 0
    first_seen:    Optional[str] = None
    last_seen:     Optional[str] = None


@dataclass
class InstanceNode:
    guid:          str
    score:         int
    ghost:         bool
    alive:         bool
    start_time:    Optional[str]
    end_time:      Optional[str]
    template_hash: Optional[str] = None


@dataclass
class BehaviourEdge:
    src_id:      str
    dst_id:      str
    rel_type:    str
    total_score: int
    count:       int
    first_seen:  str
    last_seen:   str
    techniques:  List[str]
    tactics:     List[str]
    finding_ids: List[str]
    extra:       Dict[str, Any] = field(default_factory=dict)


@dataclass
class ArtifactNode:
    id:    str
    label: str
    extra: Dict[str, Any] = field(default_factory=dict)
    sha256: Optional[str] = None
    path:   Optional[str] = None

@dataclass
class SubgraphContext:
    anchor_guid:       str
    anchor_score:      int
    instances:         List[InstanceNode]
    templates:         Dict[str, TemplateNode]
    artifacts:         List[ArtifactNode]
    edges:             List[BehaviourEdge]
    timeline:          List[Dict[str, str]]
    has_ghost_parents: bool
    total_nodes:       int
    total_edges:       int
    unvisited_guids:   Set[str]             = field(default_factory=set)
    process_tree:      Dict[str, List[str]] = field(default_factory=dict)  # parent_guid → [child_guids]
    tree_roots:        List[str]            = field(default_factory=list)   # guids with no parent in subgraph


@dataclass
class _QItem:
    guid:      str
    hops_left: int


# ══════════════════════════════════════════════════════════════════════════════

class GraphExtractor:

    def __init__(self, db: Memgraph):
        self.db = db

    # ── PUBLIC ────────────────────────────────────────────────────────────────

    def extract(
        self,
        anchor_guid:    str,
        to_investigate: Set[str],
    ) -> Optional[SubgraphContext]:
        """
        Build a SubgraphContext starting from anchor_guid,
        merging any to_investigate nodes encountered during traversal.
        """
        expand_guids, include_guids = self._collect_tree(anchor_guid, to_investigate)
        all_guids = expand_guids | include_guids

        if not all_guids:
            return None

        instances, templates = self._fetch_instances(all_guids)
        if not instances:
            return None

        edges, artifact_ids, orphan_ids = self._fetch_behaviour_edges(all_guids)

        if orphan_ids:
            orphan_instances, orphan_templates = self._fetch_instances(orphan_ids)
            # merge
            existing_guids = {i.guid for i in instances}
            instances  += [i for i in orphan_instances if i.guid not in existing_guids]
            templates  |= {k: v for k, v in orphan_templates.items() if k not in templates}
        
        artifacts                    = self._fetch_artifacts(artifact_ids)
        timeline                     = self._build_timeline(edges, instances, templates)
        process_tree, tree_roots     = self._build_process_tree(all_guids)

        instances, artifacts, edges  = self._enforce_limits(
            anchor_guid, instances, artifacts, edges
        )

        return SubgraphContext(
            anchor_guid       = anchor_guid,
            anchor_score      = next(
                (i.score for i in instances if i.guid == anchor_guid), 0
            ),
            instances         = instances,
            templates         = templates,
            artifacts         = artifacts,
            edges             = edges,
            timeline          = timeline,
            has_ghost_parents = any(
                i.ghost for i in instances if i.guid != anchor_guid
            ),
            total_nodes       = len(instances) + len(artifacts),
            total_edges       = len(edges),
            unvisited_guids   = to_investigate - expand_guids - include_guids,
            process_tree      = process_tree,
            tree_roots        = tree_roots,
        )

    # ── BFS ───────────────────────────────────────────────────────────────────

    def _collect_tree(
        self,
        anchor_guid:    str,
        to_investigate: Set[str],
    ) -> Tuple[Set[str], Set[str]]:
        """
        BFS through CHILD_OF (both directions) and lateral edges.

        expand_guids  — to_investigate nodes: fully expanded
        include_guids — all other nodes: included + behavior fetched, not expanded
        """
        expand_guids:  Set[str] = set()
        include_guids: Set[str] = set()
        queued:        Set[str] = set()

        queue: deque[_QItem] = deque()
        queue.append(_QItem(guid=anchor_guid, hops_left=HOP_INITIAL))
        queued.add(anchor_guid)

        while queue:
            item      = queue.popleft()
            guid      = item.guid
            hops_left = item.hops_left

            if guid in expand_guids:
                continue

            expand_guids.add(guid)
            include_guids.discard(guid)

            if hops_left <= 0:
                continue

            # ── CHILD_OF: parents and children ────────────────────────────
            for n in self._fetch_child_of_neighbors(guid):
                nguid = n["guid"]
                if nguid in expand_guids:
                    continue

                if nguid in to_investigate:
                    include_guids.discard(nguid)
                    if nguid not in queued:
                        queue.append(_QItem(guid=nguid, hops_left=HOP_RESET))
                        queued.add(nguid)
                else:
                    include_guids.add(nguid)
                    if nguid not in queued:
                        queue.append(_QItem(guid=nguid, hops_left=hops_left - 1))
                        queued.add(nguid)

            # ── LATERALS: injection / memory / tamper ─────────────────────
            for n in self._fetch_lateral_neighbors(guid):
                nguid  = n["guid"]
                nscore = int(n.get("score") or 0)

                if nscore == 0:
                    continue

                if nguid in expand_guids:
                    continue

                if nguid in to_investigate:
                    include_guids.discard(nguid)
                    if nguid not in queued:
                        queue.append(_QItem(guid=nguid, hops_left=HOP_RESET))
                        queued.add(nguid)
                else:
                    include_guids.add(nguid)

        include_guids -= expand_guids
        return expand_guids, include_guids

    # ── QUERIES ───────────────────────────────────────────────────────────────

    def _fetch_child_of_neighbors(self, guid: str) -> List[Dict]:
        rows = self._fetch("""
            MATCH (p:ProcessInstance {id: $guid})
            OPTIONAL MATCH (p)-[:CHILD_OF]->(parent:ProcessInstance)
            OPTIONAL MATCH (child:ProcessInstance)-[:CHILD_OF]->(p)
            WITH
                collect(DISTINCT parent) AS parents,
                collect(DISTINCT child)  AS children
            WITH parents + children AS neighbors
            UNWIND neighbors AS n
            WITH n WHERE n IS NOT NULL
            RETURN DISTINCT
                n.id    AS guid,
                n.score AS score
        """, {"guid": guid})
        return [dict(r) for r in rows if r.get("guid")]

    def _fetch_lateral_neighbors(self, guid: str) -> List[Dict]:
        rows = self._fetch("""
            MATCH (src:ProcessInstance {id: $guid})
                  -[:INJECTED_THREAD|ACCESSED_MEMORY|TAMPERED]->
                  (tgt:ProcessInstance)
            RETURN DISTINCT
                tgt.id    AS guid,
                tgt.score AS score
        """, {"guid": guid})
        return [dict(r) for r in rows if r.get("guid")]

    def _fetch_instances(
        self,
        guids: Set[str],
    ) -> Tuple[List[InstanceNode], Dict[str, TemplateNode]]:
        if not guids:
            return [], {}

        rows = self._fetch("""
            UNWIND $guids AS guid
            MATCH (p:ProcessInstance {id: guid})
            OPTIONAL MATCH (p)-[:INSTANCE_OF]->(t:ProcessTemplate)
            RETURN
                p.id         AS guid,
                p.score      AS score,
                p.ghost      AS ghost,
                p.alive      AS alive,
                p.start_time AS start_time,
                p.end_time   AS end_time,

                t.template_hash AS template_hash,
                t.image         AS image,
                t.parent_image  AS parent_image,
                t.cmdline       AS cmdline,
                t.user          AS user,
                t.description   AS description,
                t.seen_count    AS seen_count,
                t.total_score   AS total_score,
                t.first_seen    AS first_seen,
                t.last_seen     AS last_seen
        """, {"guids": list(guids)})

        instances: List[InstanceNode]      = []
        templates: Dict[str, TemplateNode] = {}

        for r in rows:
            if not r.get("guid"):
                continue

            t_hash = r.get("template_hash")

            instances.append(InstanceNode(
                guid          = r["guid"],
                score         = int(r.get("score") or 0),
                ghost         = bool(r.get("ghost")),
                alive         = bool(r.get("alive", True)),
                start_time    = r.get("start_time"),
                end_time      = r.get("end_time"),
                template_hash = t_hash,
            ))

            if t_hash and t_hash not in templates:
                templates[t_hash] = TemplateNode(
                    template_hash = t_hash,
                    image         = r.get("image"),
                    parent_image  = r.get("parent_image"),
                    cmdline       = r.get("cmdline"),
                    user          = r.get("user"),
                    description   = r.get("description"),
                    seen_count    = int(r.get("seen_count") or 0),
                    total_score   = int(r.get("total_score") or 0),
                    first_seen    = r.get("first_seen"),
                    last_seen     = r.get("last_seen"),
                )

        return instances, templates

    def _fetch_behaviour_edges(
        self,
        guids: Set[str],
    ) -> Tuple[List[BehaviourEdge], Set[str]]:
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
                r.event_type     AS event_type,
                r.size           AS size,
                r.type           AS tamper_type
            """,
            {"guids": list(guids)},
        )

        edges:        List[BehaviourEdge] = []
        artifact_ids: Set[str]            = set()

        for r in rows:
            dst_id    = r.get("dst_id") or ""
            dst_label = r.get("dst_label") or ""
            if not dst_id:
                continue

            if dst_label in ARTIFACT_LABELS:
                artifact_ids.add(dst_id)

            extra: Dict[str, Any] = {
                k: r[k] for k in (
                    "port", "protocol", "access_mask",
                    "start_function", "stream_name",
                    "event_type", "size", "tamper_type",
                )
                if r.get(k) is not None
            }

            edges.append(BehaviourEdge(
                src_id      = r["src_id"],
                dst_id      = dst_id,
                rel_type    = r["rel_type"],
                total_score = int(r.get("total_score") or 0),
                count       = int(r.get("count") or 1),
                first_seen  = r.get("first_seen") or "",
                last_seen   = r.get("last_seen")  or "",
                techniques  = r.get("techniques")  or [],
                tactics     = r.get("tactics")     or [],
                finding_ids = r.get("finding_ids") or [],
                extra       = extra,
            ))
            # Collect any process dst_ids that weren't in our original guid set
        orphan_process_ids = {
            e.dst_id for e in edges
            if e.dst_id not in guids
            and e.rel_type in LATERAL_REL_TYPES   # only processes, not artifacts
        }
        return edges, artifact_ids, orphan_process_ids  # ← pass back up


    def _fetch_artifacts(self, artifact_ids: Set[str]) -> List[ArtifactNode]:
        if not artifact_ids:
            return []

        rows = self._fetch("""
            UNWIND $ids AS aid
            MATCH (n {id: aid})
            WHERE NOT n:ProcessInstance AND NOT n:ProcessTemplate
            RETURN
                n.id         AS id,
                labels(n)[0] AS label,
                n.image      AS image,
                n.sha256     AS sha256,
                n.path       AS path
        """, {"ids": list(artifact_ids)})

        result = []
        for r in rows:
            if not r.get("id"):
                continue
            extra = {"image": r["image"]} if r.get("image") else {}
            result.append(ArtifactNode(
                id    = r["id"],
                label = r.get("label") or "Unknown",
                extra = extra,
                sha256 = r.get("sha256"),
                path   = r.get("path"),
            ))
        return result

    # ── PROCESS TREE ──────────────────────────────────────────────────────────

    def _build_process_tree(
        self,
        all_guids: Set[str],
    ) -> Tuple[Dict[str, List[str]], List[str]]:
        """
        Build parent→children map from CHILD_OF edges in the graph.
        CHILD_OF direction: (child)-[:CHILD_OF]->(parent)
        Returns (children_of dict, root_guids list).
        """
        rows = self._fetch("""
            UNWIND $guids AS guid
            MATCH (child:ProcessInstance {id: guid})-[:CHILD_OF]->(parent:ProcessInstance)
            WHERE parent.id IN $guids
            RETURN child.id AS child_guid, parent.id AS parent_guid
        """, {"guids": list(all_guids)})

        children_of: Dict[str, List[str]] = {g: [] for g in all_guids}
        has_parent:  Set[str]             = set()

        for r in rows:
            child  = r.get("child_guid")
            parent = r.get("parent_guid")
            if child and parent:
                children_of[parent].append(child)
                has_parent.add(child)

        roots = [g for g in all_guids if g not in has_parent]
        return children_of, roots

    # ── TIMELINE ──────────────────────────────────────────────────────────────

    def _build_timeline(
        self,
        edges:     List[BehaviourEdge],
        instances: List[InstanceNode],
        templates: Dict[str, TemplateNode],
    ) -> List[Dict[str, str]]:
        events = []

        for inst in instances:
            if inst.start_time and not inst.ghost:
                t     = templates.get(inst.template_hash or "")
                label = (t.image if t else None) or inst.guid
                events.append({
                    "timestamp":  inst.start_time,
                    "rel_type":   "PROCESS_START",
                    "src":        label,
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
    ) -> Tuple[List[InstanceNode], List[ArtifactNode], List[BehaviourEdge]]:

        total = len(instances) + len(artifacts)
        if total <= MAX_NODES and len(edges) <= MAX_EDGES:
            return instances, artifacts, edges

        keep_artifacts = sorted(artifacts, key=lambda a: a.id)[
            : max(0, MAX_NODES - len(instances))
        ]

        total = len(instances) + len(keep_artifacts)
        if total > MAX_NODES:
            non_anchor     = sorted(
                [i for i in instances if i.guid != anchor_guid],
                key=lambda i: -i.score,
            )[: MAX_NODES - len(keep_artifacts) - 1]
            anchor_list    = [i for i in instances if i.guid == anchor_guid]
            keep_instances = anchor_list + non_anchor
        else:
            keep_instances = instances

        valid_ids  = {i.guid for i in keep_instances} | {a.id for a in keep_artifacts}
        keep_edges = [
            e for e in edges
            if e.src_id in valid_ids and e.dst_id in valid_ids
        ][:MAX_EDGES]

        return keep_instances, keep_artifacts, keep_edges

    # ── DB HELPER ─────────────────────────────────────────────────────────────

    def _fetch(self, query: str, params: dict) -> List[Dict]:
        try:
            return list(self.db.execute_and_fetch(query, params))
        except Exception as exc:
            print(f"[GraphExtractor][FAIL] {exc}")
            return []