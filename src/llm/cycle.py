# src/detection/cycle.py

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from src.graph.Graph_Builder import GraphBuilder
from src.detection.context import build_connected_snapshot
from src.detection.llm import analyse
from src.detection.notes import NotesStore
from src.detection.watch_rules import WatchRulesStore, WATCH_RULE_SCORE_BOOST

CYCLE_SECONDS   = 30
SCORE_THRESHOLD = 4
MAX_PARALLEL    = 5      # max concurrent LLM calls per cycle

gb    = GraphBuilder()
notes = NotesStore.instance()
rules = WatchRulesStore.instance()


# ── candidate fetch ───────────────────────────────────────────────────────

def _fetch_candidates() -> list:
    """
    All unresolved ProcessInstances with score >= threshold.
    Ordered by score descending so worst cases go first.
    """
    rows = gb._fetch("""
        MATCH (p:ProcessInstance)
        WHERE p.score >= $threshold
          AND p.cycle_resolved IS NULL
          AND p.ghost = false
        OPTIONAL MATCH (p)-[:INSTANCE_OF]->(t:ProcessTemplate)
        RETURN
            p.id             AS guid,
            p.score          AS score,
            p.last_updated_at AS last_updated_at,
            t.image          AS image
        ORDER BY p.score DESC
    """, {"threshold": SCORE_THRESHOLD})
    return [dict(r) for r in rows]


# ── stagnation check ──────────────────────────────────────────────────────

def _has_new_activity(guid: str, note: dict | None) -> bool:
    """
    Returns True if anything happened to this process
    since the LLM last looked at it.
    If no note exists → always True (first time seeing it).
    """
    if note is None:
        return True

    last_llm_at = note.get("last_llm_at")
    if not last_llm_at:
        return True

    rows = gb._fetch("""
        MATCH (p:ProcessInstance {id: $guid})
        RETURN p.last_updated_at AS last_updated_at
    """, {"guid": guid})

    if not rows:
        return False

    last_updated = rows[0].get("last_updated_at")
    if not last_updated:
        return True

    return last_updated > last_llm_at


# ── result handling ───────────────────────────────────────────────────────

def _handle_result(subgraph_guids: set, snapshot: dict, report: str):
    """
    Parse the LLM report and decide what to do.

    The LLM report is free text with a VERDICT line.
    We look for:
      VERDICT: MALICIOUS   → act, clean, store watch rules
      VERDICT: SUSPICIOUS  → update note, keep watching
      VERDICT: BENIGN      → clean, no watch rule needed
      VERDICT: NEEDS_INVESTIGATION → update note, keep watching
    """
    verdict    = _extract_verdict(report)
    confidence = _extract_confidence(report)
    root       = snapshot["root"]
    nodes      = snapshot["nodes"]

    print(f"\n[CYCLE] root={root[:8]} | nodes={len(nodes)} "
          f"| verdict={verdict} | confidence={confidence:.2f}")
    print(f"[REPORT]\n{report}\n{'─'*80}")

    if verdict in ("MALICIOUS",) and confidence >= 0.75:
        # ── act: store watch rules then clean ─────────────────────
        for guid in subgraph_guids:
            node = nodes.get(guid, {})
            if node.get("score", 0) >= SCORE_THRESHOLD:
                rules.add(
                    template_hash = node.get("template_hash", ""),
                    image         = node.get("image", ""),
                    parent_image  = node.get("parent_image", ""),
                    cmdline       = node.get("cmdline", ""),
                    reason        = f"LLM verdict MALICIOUS (confidence={confidence:.2f}): "
                                    + _extract_first_line(report),
                    ttl_hours     = 2,
                )

        _resolve_subgraph(subgraph_guids, reason="llm_malicious")
        notes.delete_many(list(subgraph_guids))

    elif verdict == "BENIGN" and confidence >= 0.80:
        # ── confirmed benign: clean without watch rule ─────────────
        _resolve_subgraph(subgraph_guids, reason="llm_benign")
        notes.delete_many(list(subgraph_guids))

    else:
        # ── not sure: update note for every guid in subgraph ──────
        # summarize the report as a note for each guid
        summary = _summarize_report(report)
        for guid in subgraph_guids:
            node  = nodes.get(guid, {})
            score = int(node.get("score") or 0)
            notes.upsert(guid, summary, score)


def _resolve_subgraph(guids: set, reason: str):
    for guid in guids:
        gb._run("""
            MATCH (p:ProcessInstance {id: $guid})
            SET p.cycle_resolved        = true,
                p.cycle_resolved_reason = $reason,
                p.cycle_resolved_at     = $ts
        """, {
            "guid":   guid,
            "reason": reason,
            "ts":     datetime.utcnow().isoformat(),
        })


# ── LLM report parsing helpers ────────────────────────────────────────────

def _extract_verdict(report: str) -> str:
    for line in report.upper().splitlines():
        for v in ("MALICIOUS", "SUSPICIOUS", "BENIGN", "NEEDS_INVESTIGATION"):
            if v in line and "VERDICT" in line:
                return v
    # fallback: scan entire report
    for v in ("MALICIOUS", "SUSPICIOUS", "BENIGN", "NEEDS_INVESTIGATION"):
        if v in report.upper():
            return v
    return "NEEDS_INVESTIGATION"


def _extract_confidence(report: str) -> float:
    import re
    matches = re.findall(r"confidence[:\s]+([01]\.\d+)", report, re.IGNORECASE)
    if matches:
        try:
            return float(matches[0])
        except ValueError:
            pass
    return 0.5


def _extract_first_line(report: str) -> str:
    for line in report.splitlines():
        if line.strip():
            return line.strip()[:120]
    return ""


def _summarize_report(report: str) -> str:
    """
    Store the first 800 characters of the report as the note.
    The LLM will receive this as 'previous note' next cycle.
    """
    return report.strip()[:800]


# ── single cycle ─────────────────────────────────────────────────────────

def run_cycle():
    candidates = _fetch_candidates()
    if not candidates:
        return

    remaining = {c["guid"] for c in candidates}

    print(f"[CYCLE] {len(remaining)} candidates at {datetime.utcnow().isoformat()}")

    # collect jobs: each job is one connected subgraph
    jobs = []
    while remaining:
        root     = next(iter(remaining))
        note     = notes.get(root)

        if not _has_new_activity(root, note):
            remaining.discard(root)
            continue

        # build connected subgraph — this tells us which guids are covered
        snapshot = build_connected_snapshot(root)
        covered  = set(snapshot["nodes"].keys())
        remaining -= covered

        # attach previous note to snapshot
        snapshot["previous_note"] = note.get("note") if note else None

        jobs.append((covered, snapshot))

    if not jobs:
        return

    # run LLM calls in parallel
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL) as pool:
        futures = {
            pool.submit(analyse, snapshot): (covered, snapshot)
            for covered, snapshot in jobs
        }
        for future in as_completed(futures):
            covered, snapshot = futures[future]
            try:
                report = future.result()
                _handle_result(covered, snapshot, report)
            except Exception as e:
                print(f"[CYCLE ERROR] subgraph={snapshot['root'][:8]} error={e}")


# ── forever loop ──────────────────────────────────────────────────────────

def _run_forever():
    while True:
        start = time.time()
        try:
            run_cycle()
        except Exception as e:
            print(f"[CYCLE FATAL] {e}")
        elapsed = time.time() - start
        time.sleep(max(0, CYCLE_SECONDS - elapsed))


def start():
    t = threading.Thread(target=_run_forever, daemon=True)
    t.name = "detection-cycle"
    t.start()
    print(f"[CYCLE] Started — interval={CYCLE_SECONDS}s threshold={SCORE_THRESHOLD}")