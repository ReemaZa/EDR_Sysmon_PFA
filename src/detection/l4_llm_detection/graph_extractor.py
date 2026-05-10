"""
graph_extractor.py  —  Pulls a bounded SubgraphContext from Memgraph.
Aligned to graph_builder.py v4.0 schema.
v3.0 optimizations over v2.0 batch BFS:
  - BFS queries filter out already-visited nodes in Cypher (no wasted rows)
  - _fetch_instances folds in orphan resolution (one call, not two)
  - _build_process_tree derived from already-fetched edge data (zero DB calls)
  - _fetch_artifacts uses labeled UNION scan instead of label-free MATCH
  - Post-BFS collapsed to 2 round-trips: (instances) + (edges+artifacts merged)
  - _fetch_behaviour_edges returns artifact rows inline — no second artifact query
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
    "CREATED", "CONNECTED", "LOADED_DRIVER", "LOADED_IMAGE",
    "INJECTED_THREAD", "ACCESSED_MEMORY", "CREATED_FILE",
    "MODIFIED_REGISTRY", "QUERIED_DNS", "DELETED",
    "TIMESTOMPED", "WROTE_ADS", "TAMPERED",
}
LATERAL_REL_TYPES = {"INJECTED_THREAD", "ACCESSED_MEMORY", "TAMPERED"}
ARTIFACT_LABELS   = {"File", "Network", "Registry", "DNS", "Driver", "Image"}

# Pre-built for query injection (never changes at runtime)
_REL_FILTER      = "|".join(BEHAVIOUR_REL_TYPES)
_ARTIFACT_LABELS = list(ARTIFACT_LABELS)


# ── data models ───────────────────────────────────────────────────────────────

@dataclass
class TemplateNode:
    template_hash: str
    image:         Optional[str] = None
    parent_image:  Optional[str] = None
    cmdline:       Optional[str] = None
    description:   Optional[str] = None
    seen_count:    int           = 0
    total_score:   int           = 0
    first_seen:    Optional[str] = None
    last_seen:     Optional[str] = None

@dataclass
class InstanceNode:
    guid:           str
    score:          int
    ghost:          bool
    alive:          bool
    start_time:     Optional[str]
    end_time:       Optional[str]
    template_hash:  Optional[str] = None
    user:           Optional[str] = None
    pending_action: Optional[str] = None

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
    id:             str
    label:          str
    extra:          Dict[str, Any] = field(default_factory=dict)
    sha256:         Optional[str]  = None
    path:           Optional[str]  = None
    pending_action: Optional[str]  = None

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
    process_tree:      Dict[str, List[str]] = field(default_factory=dict)
    tree_roots:        List[str]            = field(default_factory=list)

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
        # ── Phase 1: BFS  (2 × depth round-trips, visited filter in Cypher) ──
        expand_guids, include_guids = self._collect_tree_batch(anchor_guid, to_investigate)
        all_guids = expand_guids | include_guids
        if not all_guids:
            return None

        # ── Phase 2: fetch instances (1 round-trip, orphans folded in) ────────
        instances, templates = self._fetch_instances(all_guids)
        if not instances:
            return None

        # ── Phase 3: fetch edges + artifact nodes (1 round-trip) ─────────────
        edges, artifacts, orphan_ids = self._fetch_edges_and_artifacts(all_guids)

        # ── Phase 4: fold orphans into already-fetched data (0 extra DB calls
        #    if orphans already seen; 1 extra call only when truly new) ─────────
        if orphan_ids - all_guids:
            new_orphan_guids = orphan_ids - all_guids
            o_instances, o_templates = self._fetch_instances(new_orphan_guids)
            existing = {i.guid for i in instances}
            instances += [i for i in o_instances if i.guid not in existing]
            templates |= {k: v for k, v in o_templates.items() if k not in templates}

        # ── Phase 5: derive process tree from edge data — zero DB calls ───────
        process_tree, tree_roots = self._derive_process_tree(all_guids, edges)

        # ── Phase 6: timeline + limits — pure Python ─────────────────────────
        timeline                    = self._build_timeline(edges, instances, templates)
        """instances, artifacts, edges = self._enforce_limits(anchor_guid, instances, artifacts, edges)"""

        return SubgraphContext(
            anchor_guid       = anchor_guid,
            anchor_score      = next((i.score for i in instances if i.guid == anchor_guid), 0),
            instances         = instances,
            templates         = templates,
            artifacts         = artifacts,
            edges             = edges,
            timeline          = timeline,
            has_ghost_parents = any(i.ghost for i in instances if i.guid != anchor_guid),
            total_nodes       = len(instances) + len(artifacts),
            total_edges       = len(edges),
            unvisited_guids   = to_investigate - expand_guids - include_guids,
            process_tree      = process_tree,
            tree_roots        = tree_roots,
        )

    # ── BATCH BFS ─────────────────────────────────────────────────────────────

    def _collect_tree_batch(
        self,
        anchor_guid:    str,
        to_investigate: Set[str],
    ) -> Tuple[Set[str], Set[str]]:
        expand_guids:  Set[str]       = set()
        include_guids: Set[str]       = set()
        frontier:      Dict[str, int] = {anchor_guid: HOP_INITIAL}

        while frontier:
            for guid in frontier:
                expand_guids.add(guid)
                include_guids.discard(guid)

            active = {g: h for g, h in frontier.items() if h > 0}
            if not active:
                break

            next_frontier: Dict[str, int] = {}
            already_seen = expand_guids  # passed into Cypher to skip in DB

            # ── CHILD_OF batch (visited nodes excluded inside Cypher) ──────
            for row in self._fetch_child_of_batch(set(active.keys()), already_seen):
                nguid    = row["guid"]
                src_guid = row["src_guid"]
                new_hops = HOP_RESET if nguid in to_investigate else active[src_guid] - 1

                if nguid in to_investigate:
                    include_guids.discard(nguid)
                else:
                    include_guids.add(nguid)

                if nguid not in next_frontier or next_frontier[nguid] < new_hops:
                    next_frontier[nguid] = new_hops

            # ── Lateral batch (visited nodes excluded inside Cypher) ───────
            for row in self._fetch_lateral_batch(set(active.keys()), already_seen):
                nguid  = row["guid"]
                nscore = int(row.get("score") or 0)
                if nscore == 0:
                    continue
                if nguid in to_investigate:
                    include_guids.discard(nguid)
                    if nguid not in next_frontier or next_frontier[nguid] < HOP_RESET:
                        next_frontier[nguid] = HOP_RESET
                else:
                    include_guids.add(nguid)

            frontier = {g: h for g, h in next_frontier.items() if g not in expand_guids}

        include_guids -= expand_guids
        return expand_guids, include_guids

    # ── BATCH NEIGHBOR QUERIES (visited filter pushed into Cypher) ────────────

    def _fetch_child_of_batch(
        self,
        guids:   Set[str],
        visited: Set[str],
    ) -> List[Dict]:
        """
        Excludes already-visited nodes inside the query so Memgraph never
        returns rows that will be discarded in Python.
        """
        if not guids:
            return []
        rows = self._fetch("""
            UNWIND $guids AS src_guid
            MATCH (p:ProcessInstance {id: src_guid})
            OPTIONAL MATCH (p)-[:CHILD_OF]->(parent:ProcessInstance)
                WHERE NOT parent.id IN $visited
            OPTIONAL MATCH (child:ProcessInstance)-[:CHILD_OF]->(p)
                WHERE NOT child.id IN $visited
            WITH src_guid,
                 collect(DISTINCT {guid: parent.id, score: parent.score}) +
                 collect(DISTINCT {guid: child.id,  score: child.score})  AS neighbors
            UNWIND neighbors AS n
            WITH src_guid, n WHERE n.guid IS NOT NULL
            RETURN DISTINCT src_guid AS src_guid, n.guid AS guid, n.score AS score
        """, {"guids": list(guids), "visited": list(visited)})
        return [dict(r) for r in rows if r.get("guid")]

    def _fetch_lateral_batch(
        self,
        guids:   Set[str],
        visited: Set[str],
    ) -> List[Dict]:
        if not guids:
            return []
        rows = self._fetch("""
            UNWIND $guids AS src_guid
            MATCH (src:ProcessInstance {id: src_guid})
                  -[:INJECTED_THREAD|ACCESSED_MEMORY|TAMPERED]->
                  (tgt:ProcessInstance)
            WHERE NOT tgt.id IN $visited
            RETURN DISTINCT src_guid AS src_guid, tgt.id AS guid, tgt.score AS score
        """, {"guids": list(guids), "visited": list(visited)})
        return [dict(r) for r in rows if r.get("guid")]

    # ── MERGED EDGES + ARTIFACTS (1 round-trip replaces 2) ───────────────────

    def _fetch_edges_and_artifacts(
        self,
        guids: Set[str],
    ) -> Tuple[List[BehaviourEdge], List[ArtifactNode], Set[str]]:
        """
        Single query that returns both behaviour edges AND artifact node
        properties inline.  Eliminates the separate _fetch_artifacts call.

        Uses labeled UNION arms instead of label-free MATCH so Memgraph
        can use the per-label id index on every arm.
        """
        if not guids:
            return [], [], set()

        rows = self._fetch(
            f"""
            UNWIND $guids AS guid
            MATCH (src:ProcessInstance {{id: guid}})-[r:{_REL_FILTER}]->(dst)
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
                r.type           AS tamper_type,
                dst.sha256           AS dst_sha256,
                dst.path             AS dst_path,
                dst.image            AS dst_image,
                dst.pending_action   AS dst_pending_action
            """,
            {"guids": list(guids)},
        )

        edges:          List[BehaviourEdge] = []
        artifact_map:   Dict[str, ArtifactNode] = {}   # dedup by id
        orphan_ids:     Set[str]            = set()

        for r in rows:
            dst_id    = r.get("dst_id") or ""
            dst_label = r.get("dst_label") or ""
            rel_type  = r.get("rel_type") or ""
            if not dst_id:
                continue

            # ── collect artifact node inline ──────────────────────────────
            if dst_label in ARTIFACT_LABELS and dst_id not in artifact_map:
                extra = {"image": r["dst_image"]} if r.get("dst_image") else {}
                artifact_map[dst_id] = ArtifactNode(
                    id             = dst_id,
                    label          = dst_label,
                    extra          = extra,
                    sha256         = r.get("dst_sha256"),
                    path           = r.get("dst_path"),
                    pending_action = r.get("dst_pending_action"),
                )

            # ── orphan process destinations (laterals) ────────────────────
            if rel_type in LATERAL_REL_TYPES and dst_id not in guids:
                orphan_ids.add(dst_id)

            extra_edge = {
                k: r[k] for k in (
                    "port", "protocol", "access_mask", "start_function",
                    "stream_name", "event_type", "size", "tamper_type",
                )
                if r.get(k) is not None
            }
            edges.append(BehaviourEdge(
                src_id      = r["src_id"],
                dst_id      = dst_id,
                rel_type    = rel_type,
                total_score = int(r.get("total_score") or 0),
                count       = int(r.get("count") or 1),
                first_seen  = r.get("first_seen") or "",
                last_seen   = r.get("last_seen")  or "",
                techniques  = r.get("techniques")  or [],
                tactics     = r.get("tactics")     or [],
                finding_ids = r.get("finding_ids") or [],
                extra       = extra_edge,
            ))

        return edges, list(artifact_map.values()), orphan_ids

    # ── PROCESS TREE: derived from edges, zero DB calls ───────────────────────

    def _derive_process_tree(
        self,
        all_guids: Set[str],
        edges:     List[BehaviourEdge],
    ) -> Tuple[Dict[str, List[str]], List[str]]:
        """
        CHILD_OF is mirrored by the CREATED edge (Event-1 writes both).
        We derive parent→children from CREATED edges already in memory
        instead of issuing another query.
        """
        children_of: Dict[str, List[str]] = {g: [] for g in all_guids}
        has_parent:  Set[str]             = set()

        for e in edges:
            if e.rel_type == "CREATED" and e.src_id in all_guids and e.dst_id in all_guids:
                children_of[e.src_id].append(e.dst_id)
                has_parent.add(e.dst_id)

        roots = [g for g in all_guids if g not in has_parent]
        return children_of, roots

    # ── INSTANCES (unchanged, but now also covers orphans in one call) ────────

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
            OPTIONAL MATCH (p)-[:RAN_AS]->(u:User)
            RETURN
                p.id             AS guid,
                p.score          AS score,
                p.ghost          AS ghost,
                p.alive          AS alive,
                p.start_time     AS start_time,
                p.end_time       AS end_time,
                p.pending_action AS pending_action,
                t.template_hash  AS template_hash,
                t.image          AS image,
                t.parent_image   AS parent_image,
                t.cmdline        AS cmdline,
                t.description    AS description,
                t.seen_count     AS seen_count,
                t.total_score    AS total_score,
                t.first_seen     AS first_seen,
                t.last_seen      AS last_seen,
                CASE
                    WHEN u.pending_action IS NOT NULL AND u.pending_action <> "alert"
                    THEN u.id + ' [' + u.pending_action + ']'
                    ELSE u.id
                END AS user
        """, {"guids": list(guids)})

        instances: List[InstanceNode]      = []
        templates: Dict[str, TemplateNode] = {}

        for r in rows:
            if not r.get("guid"):
                continue
            t_hash = r.get("template_hash")
            instances.append(InstanceNode(
                guid           = r["guid"],
                score          = int(r.get("score") or 0),
                ghost          = bool(r.get("ghost")),
                alive          = bool(r.get("alive", True)),
                start_time     = r.get("start_time"),
                end_time       = r.get("end_time"),
                template_hash  = t_hash,
                user           = r.get("user"),
                pending_action = r.get("pending_action"),
            ))
            if t_hash and t_hash not in templates:
                templates[t_hash] = TemplateNode(
                    template_hash = t_hash,
                    image         = r.get("image"),
                    parent_image  = r.get("parent_image"),
                    cmdline       = r.get("cmdline"),
                    description   = r.get("description"),
                    seen_count    = int(r.get("seen_count") or 0),
                    total_score   = int(r.get("total_score") or 0),
                    first_seen    = r.get("first_seen"),
                    last_seen     = r.get("last_seen"),
                )
        return instances, templates

    # ── TIMELINE + LIMITS (pure Python, unchanged) ────────────────────────────

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
            keep_instances = [i for i in instances if i.guid == anchor_guid] + non_anchor
        else:
            keep_instances = instances

        valid_ids  = {i.guid for i in keep_instances} | {a.id for a in keep_artifacts}
        keep_edges = [
            e for e in edges
            if e.src_id in valid_ids and e.dst_id in valid_ids
        ][:MAX_EDGES]
        return keep_instances, keep_artifacts, keep_edges

    def _fetch(self, query: str, params: dict) -> List[Dict]:
        try:
            return list(self.db.execute_and_fetch(query, params))
        except Exception as exc:
            print(f"[GraphExtractor][FAIL] {exc}")
            return []