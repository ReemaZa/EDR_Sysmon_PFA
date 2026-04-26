# src/detection/llm.py

import anthropic
from src.graph.Graph_Builder import GraphBuilder

client = anthropic.Anthropic()
MODEL  = "claude-sonnet-4-20250514"
gb     = GraphBuilder()

SYSTEM = """You are a senior threat analyst reviewing EDR telemetry from a Windows endpoint.

You will receive a connected process subgraph — one or more processes linked through \
parent/child relationships, process injection, memory access, or shared artifacts. \
They form a single investigation case.

You may also receive a PREVIOUS NOTE — your own summary from an earlier cycle. \
Use it as context. Do not repeat what you already noted unless it is now confirmed \
or contradicted by new evidence.

Your report must cover:

1. OVERVIEW
   What is happening. One paragraph.

2. PROCESS CHAIN
   Walk the relationships. Flag anything suspicious.
   (office app spawning powershell, LOLBins, unusual parent/child, etc.)

3. BEHAVIORAL ANALYSIS
   For each significant process: what did it do?
   Reference specific artifacts, techniques, finding titles.

4. INDICATORS OF COMPROMISE
   Every concrete IOC: IPs, domains, file paths, registry keys, pipe names.

5. MITRE ATT&CK MAPPING
   Specific techniques with T-numbers.

6. VERDICT
   Line must be exactly:
   VERDICT: <MALICIOUS|SUSPICIOUS|BENIGN|NEEDS_INVESTIGATION>
   CONFIDENCE: <0.0 to 1.0>
   One sentence justification.

7. RECOMMENDED ACTIONS
   Specific: which guid to kill, which IP to block, which file to quarantine.
   Each marked IMMEDIATE or DEFERRED.

Be specific. Use actual values from the data."""


def build_prompt(snapshot: dict) -> str:
    nodes     = snapshot["nodes"]
    templates = snapshot["templates"]
    movements = snapshot["movements"]
    titles    = snapshot["finding_titles"]
    root      = snapshot["root"]

    lines = [f"=== CASE | root={root} | processes={len(nodes)} | templates={len(templates)} ===\n"]

    if snapshot.get("previous_note"):
        lines.append("=== YOUR PREVIOUS NOTE ===")
        lines.append(snapshot["previous_note"])
        lines.append("")

    # ── templates once ─────────────────────────────────────────────
    lines.append("=== TEMPLATES ===")
    for h, t in templates.items():
        flags = []
        if t.get("known_good"): flags.append("KNOWN_GOOD")
        if t.get("known_bad"):  flags.append("KNOWN_BAD")
        lines.append(
            f"  [{h[:12]}]"
            f"  image={t.get('image')}"
            f"  parent={t.get('parent_image')}"
            f"  user={t.get('user')}"
            f"  cmdline={t.get('cmdline')}"
            f"  seen={t.get('seen_count', 0)}"
            f"  total_score={t.get('template_total_score', 0)}"
            f"  verdict_history={t.get('llm_verdict_history') or 'none'}"
            f"  fp={t.get('fp_count', 0)} fn={t.get('fn_count', 0)}"
            + (f"  FLAGS={','.join(flags)}" if flags else "")
        )

    # ── processes reference template hash only ─────────────────────
    lines.append("\n=== PROCESSES ===")
    for guid, p in nodes.items():
        marker = " [ROOT]" if guid == root else ""
        if int(p.get("score") or 0) >= 5:
            marker += " [SUSPICIOUS]"
        lines.append(
            f"  {guid}{marker}"
            f"  template={str(p.get('template_hash') or '')[:12]}"
            f"  score={p.get('score', 0)}"
            f"  alive={p.get('alive')}"
            f"  ghost={p.get('ghost')}"
            f"  start={p.get('start_time')}"
            f"  end={p.get('end_time') or 'running'}"
        )

def _lifetime_str(p: dict) -> str:
    try:
        from datetime import datetime
        s = datetime.fromisoformat(p["start_time"])
        e = datetime.fromisoformat(p["end_time"])
        return f"{(e - s).total_seconds():.1f}s"
    except Exception:
        return "still running" if p.get("alive") else "unknown"


def _collect_process_relationships(guids: list) -> list:
    if len(guids) < 2:
        return []
    rows = gb._fetch("""
        MATCH (a:ProcessInstance)-[r]-(b:ProcessInstance)
        WHERE a.id IN $guids AND b.id IN $guids AND id(a) < id(b)
        OPTIONAL MATCH (a)-[:INSTANCE_OF]->(ta:ProcessTemplate)
        OPTIONAL MATCH (b)-[:INSTANCE_OF]->(tb:ProcessTemplate)
        RETURN
            a.id     AS guid_a,
            ta.image AS image_a,
            type(r)  AS rel,
            b.id     AS guid_b,
            tb.image AS image_b
    """, {"guids": guids})
    return [
        f"{r.get('image_a','?')} ({r.get('guid_a','')[:8]})"
        f" -[{r.get('rel')}]->"
        f" {r.get('image_b','?')} ({r.get('guid_b','')[:8]})"
        for r in rows
    ]


def analyse(snapshot: dict) -> str:
    prompt   = build_prompt(snapshot)
    response = client.messages.create(
        model      = MODEL,
        max_tokens = 2048,
        system     = SYSTEM,
        messages   = [{"role": "user", "content": prompt}],
    )
    return response.content[0].text






    # ... relationships and movements unchanged ...