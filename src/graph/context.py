# src/detection/context.py

from src.graph.Graph_Builder import GraphBuilder
from src.detection.findings import get_finding_titles

gb = GraphBuilder()

SCORE_THRESHOLD = 5


def build_connected_snapshot(root_guid: str) -> dict:
    from collections import deque

    visited   = set()
    queue     = deque([root_guid])
    nodes     = {}       # guid → instance data only (no template fields)
    templates = {}       # template_hash → template data
    movements = []

    while queue:
        guid = queue.popleft()
        if guid in visited:
            continue
        visited.add(guid)

        node, template = _fetch_node(guid)
        if not node:
            continue

        nodes[guid] = node

        if template and template["template_hash"]:
            templates[template["template_hash"]] = template

        neighbors = _fetch_connected_processes(guid)
        for n, t in neighbors:
            nguid = n["guid"]
            if nguid not in nodes:
                nodes[nguid] = n
            if t and t["template_hash"]:
                templates[t["template_hash"]] = t
            if nguid not in visited:
                queue.append(nguid)

        movements.extend(_fetch_movements(guid))

    all_finding_ids = list({
        fid
        for m in movements
        for fid in (m.get("finding_ids") or [])
        if fid
    })

    return {
        "root":           root_guid,
        "nodes":          nodes,       # guid → {guid, score, alive, template_hash, ...}
        "templates":      templates,   # hash → {image, cmdline, seen_count, ...}
        "movements":      movements,
        "finding_titles": get_finding_titles(all_finding_ids),
    }


def _fetch_node(guid: str) -> tuple[dict | None, dict | None]:
    rows = gb._fetch("""
        MATCH (p:ProcessInstance {id: $guid})
        OPTIONAL MATCH (p)-[:INSTANCE_OF]->(t:ProcessTemplate)
        RETURN
            p.id              AS guid,
            p.score           AS score,
            p.alive           AS alive,
            p.ghost           AS ghost,
            p.start_time      AS start_time,
            p.end_time        AS end_time,
            p.last_updated_at AS last_updated_at,

            t.template_hash       AS template_hash,
            t.image               AS image,
            t.parent_image        AS parent_image,
            t.cmdline             AS cmdline,
            t.user                AS user,
            t.seen_count          AS seen_count,
            t.total_score         AS template_total_score,
            t.first_seen          AS template_first_seen,
            t.last_seen           AS template_last_seen,
            t.known_good          AS known_good,
            t.known_bad           AS known_bad,
            t.llm_verdict_history AS llm_verdict_history,
            t.fp_count            AS fp_count,
            t.fn_count            AS fn_count
    """, {"guid": guid})

    if not rows:
        return None, None

    row = dict(rows[0])

    # split into instance vs template
    instance = {
        "guid":           row["guid"],
        "score":          row["score"],
        "alive":          row["alive"],
        "ghost":          row["ghost"],
        "start_time":     row["start_time"],
        "end_time":       row["end_time"],
        "last_updated_at": row["last_updated_at"],
        "template_hash":  row["template_hash"],
    }

    template = None
    if row.get("template_hash"):
        template = {
            "template_hash":        row["template_hash"],
            "image":                row["image"],
            "parent_image":         row["parent_image"],
            "cmdline":              row["cmdline"],
            "user":                 row["user"],
            "seen_count":           row["seen_count"],
            "template_total_score": row["template_total_score"],
            "template_first_seen":  row["template_first_seen"],
            "template_last_seen":   row["template_last_seen"],
            "known_good":           row["known_good"],
            "known_bad":            row["known_bad"],
            "llm_verdict_history":  row["llm_verdict_history"],
            "fp_count":             row["fp_count"],
            "fn_count":             row["fn_count"],
        }

    return instance, template


def _fetch_connected_processes(guid: str) -> list[tuple[dict, dict | None]]:
    rows = gb._fetch("""
        MATCH (p:ProcessInstance {id: $guid})-[r]-(neighbor:ProcessInstance)
        OPTIONAL MATCH (neighbor)-[:INSTANCE_OF]->(t:ProcessTemplate)
        RETURN DISTINCT
            neighbor.id           AS guid,
            neighbor.score        AS score,
            neighbor.alive        AS alive,
            neighbor.ghost        AS ghost,
            neighbor.start_time   AS start_time,
            neighbor.end_time     AS end_time,

            t.template_hash       AS template_hash,
            t.image               AS image,
            t.parent_image        AS parent_image,
            t.cmdline             AS cmdline,
            t.user                AS user,
            t.seen_count          AS seen_count,
            t.total_score         AS template_total_score,
            t.known_good          AS known_good,
            t.known_bad           AS known_bad,
            t.llm_verdict_history AS llm_verdict_history,
            t.fp_count            AS fp_count,
            t.fn_count            AS fn_count,

            type(r)               AS rel_type
    """, {"guid": guid})

    result = []
    for row in rows:
        row = dict(row)
        instance = {
            "guid":          row["guid"],
            "score":         row["score"],
            "alive":         row["alive"],
            "ghost":         row["ghost"],
            "start_time":    row["start_time"],
            "end_time":      row["end_time"],
            "template_hash": row["template_hash"],
            "rel_type":      row["rel_type"],
        }
        template = None
        if row.get("template_hash"):
            template = {
                "template_hash":        row["template_hash"],
                "image":                row["image"],
                "parent_image":         row["parent_image"],
                "cmdline":              row["cmdline"],
                "user":                 row["user"],
                "seen_count":           row["seen_count"],
                "template_total_score": row["template_total_score"],
                "known_good":           row["known_good"],
                "known_bad":            row["known_bad"],
                "llm_verdict_history":  row["llm_verdict_history"],
                "fp_count":             row["fp_count"],
                "fn_count":             row["fn_count"],
            }
        result.append((instance, template))

    return result