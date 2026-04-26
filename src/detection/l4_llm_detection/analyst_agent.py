"""
analyst_agent.py  —  LLM 1: SubgraphContext → AttackSummary

Analyses the raw process graph and produces a structured attack summary.
Does NOT produce response actions — that is ResponderAgent's job.

Handoff:
    summary.should_respond = True  →  caller spawns ResponderAgent in new thread
    Thresholds: MALICIOUS (any severity) | SUSPICIOUS + CRITICAL/HIGH

WHAT WAS KEPT vs REMOVED on edges:
    KEPT    techniques  — from Sigma rules, ground truth ATT&CK mapping
    KEPT    tactics     — from Sigma rules, ground truth
    KEPT    count       — frequency is a signal (beaconing, ransomware spray)
    KEPT    extra       — port, protocol, access_mask, etc. operationally relevant
    REMOVED finding_ids — internal Sigma rule IDs, LLM cannot use them

WHAT WAS REMOVED from templates:
    REMOVED seen_count / total_score / first_seen / last_seen — prevalence noise
    REMOVED full template_hash — 12-char prefix is enough for cross-referencing
    REMOVED ghost inferred_binaries — guessed parent images mislead analysis
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import json
import re
from typing import Any, Dict, List, Optional

from src.detection.l4_llm_detection.l4_models import (
    InvestigationCase,
    SubgraphContext,
)

_ALWAYS_RESPOND  = {"MALICIOUS"}
_RESPOND_IF_HIGH = {"SUSPICIOUS"}
_HIGH_SEVERITIES = {"CRITICAL", "HIGH"}


# ── Handoff dataclass ─────────────────────────────────────────────────────────

@dataclass
class AttackSummary:
    """
    Output of LLM 1. Passed directly to ResponderAgent.
    Contains everything the responder needs, nothing it doesn't.
    """
    case_id:          str
    anchor_guid:      str
    verdict:          str             # MALICIOUS | SUSPICIOUS | BENIGN
    severity:         str             # CRITICAL | HIGH | MEDIUM | LOW
    confidence:       str             # HIGH | MEDIUM | LOW
    attack_name:      str
    summary:          str             # 3-sentence max: what, why, key evidence
    confidence_note:  Optional[str]   # missing telemetry, or null
    mitre_techniques: List[str]       # ["T1059.001", …]
    mitre_tactics:    List[str]       # ["execution", …]

    # Attack chain — ordered steps, one per edge/spawn event
    # [{ step, image, guid, action, target, technique, tactic, count }]
    attack_chain: List[Dict] = field(default_factory=list)

    # Processes and their roles
    # [{ guid, image, pid, alive, score, role }]
    # role: patient_zero | c2_beacon | injector | injected | dropper | lateral | suspicious
    processes: List[Dict] = field(default_factory=list)

    # Raw IOCs — responder decides the action
    # [{ type: ip|domain|hash|process_name, value, context }]
    iocs: List[Dict] = field(default_factory=list)

    # Files touched — responder decides quarantine vs deletion
    # [{ path, event: created|modified|deleted|timestomped|ads, context }]
    files: List[Dict] = field(default_factory=list)

    # Windows accounts used or created by attacker
    identities: List[str] = field(default_factory=list)

    # Ghost guids and what they hide
    # [{ guid, implication }]
    gaps: List[Dict] = field(default_factory=list)

    # ── Handoff control ───────────────────────────────────────────────────────
    should_respond:   bool = False
    raw_llm_response: str  = ""


# ══════════════════════════════════════════════════════════════════════════════

class AnalystAgent:

    def analyse(
        self,
        case:     InvestigationCase,
        subgraph: SubgraphContext,
    ) -> AttackSummary:
        try:
            prompt  = self._build_prompt(case, subgraph)
            raw     = self._call_llm(prompt)
            summary = self._parse(raw, case, subgraph)
            return summary
        except Exception as exc:
            print(f"[Analyst][ERROR] case={case.case_id[:8]}: {exc}")
            return self._error_summary(case, subgraph, str(exc))

    # ── PROMPT ────────────────────────────────────────────────────────────────

    def _build_prompt(self, case: InvestigationCase, subgraph: SubgraphContext) -> str:
        sections = [
            self._s_header(case, subgraph),
            self._s_process_tree(subgraph),
            self._s_identities(subgraph),
            self._s_behaviours(subgraph),
            self._s_gaps(subgraph),
            self._s_previous(case),
            self._s_task(),
        ]
        return "\n\n".join(s for s in sections if s)

    # ── SECTION 1: HEADER ─────────────────────────────────────────────────────

    def _s_header(self, case: InvestigationCase, sg: SubgraphContext) -> str:
        return (
            f"CASE: {case.case_id}\n"
            f"ANCHOR: {sg.anchor_guid}  score={sg.anchor_score}\n"
            f"GRAPH: {len(sg.instances)} processes  "
            f"{len(sg.artifacts)} artifacts  {sg.total_edges} edges"
        )

    # ── SECTION 2: PROCESS TREE ───────────────────────────────────────────────

    def _s_process_tree(self, sg: SubgraphContext) -> str:
        if not sg.instances:
            return ""

        inst_map = {i.guid: i for i in sg.instances}
        lines    = ["PROCESS TREE:"]

        def _render(guid: str, depth: int):
            inst = inst_map.get(guid)
            if not inst:
                return
            prefix  = "  " * depth + ("└─ " if depth else "")
            tags    = []
            if inst.guid == sg.anchor_guid: tags.append("ANCHOR")
            if inst.ghost:                  tags.append("GHOST")
            if not inst.alive:              tags.append("dead")
            tag_str = f"  [{','.join(tags)}]" if tags else ""
            t_short = (inst.template_hash or "")[:12] or "no-tmpl"
            lines.append(
                f"{prefix}score={inst.score}  tmpl={t_short}  guid={inst.guid}{tag_str}"
            )
            for child in sg.process_tree.get(guid, []):
                _render(child, depth + 1)

        for root in sg.tree_roots:
            _render(root, 0)

        return "\n".join(lines)

    # ── SECTION 3: IDENTITIES ─────────────────────────────────────────────────
    # image, cmdline, user, spawned-by — the four fields that matter.
    # Prevalence stats dropped (seen_count, total_score, date windows).
    # Full hash dropped — 12-char prefix is enough for tree cross-referencing.

    def _s_identities(self, sg: SubgraphContext) -> str:
        if not sg.templates:
            return ""

        lines = ["PROCESS IDENTITIES:"]
        for tmpl in sg.templates.values():
            t_short = tmpl.template_hash[:12]
            lines.append(f"\n  tmpl={t_short}")
            lines.append(f"    image     : {tmpl.image or '?'}")
            if tmpl.parent_image:
                lines.append(f"    spawned-by: {tmpl.parent_image}")
            if tmpl.cmdline:
                lines.append(f"    cmdline   : {tmpl.cmdline}")
            if tmpl.user:
                lines.append(f"    user      : {tmpl.user}")

        return "\n".join(lines)

    # ── SECTION 4: BEHAVIOURS ─────────────────────────────────────────────────
    # techniques + tactics kept — Sigma rule ground truth, not LLM inference.
    # count kept — frequency signals beaconing, spray, enumeration.
    # finding_ids removed — internal rule IDs the LLM cannot act on.

    def _s_behaviours(self, sg: SubgraphContext) -> str:
        if not sg.edges:
            return ""

        inst_map = {i.guid: i for i in sg.instances}
        art_map  = {a.id: a for a in sg.artifacts}

        def _resolve(node_id: str) -> str:
            inst = inst_map.get(node_id)
            if inst:
                t     = sg.templates.get(inst.template_hash or "")
                image = (t.image if t else None) or "?"
                return f"{image} (guid={node_id[:8]}…)"
            art = art_map.get(node_id)
            if art:
                label = art.extra.get("image") or node_id[:48]
                return f"{art.label}:{label}"
            return f"[MISSING:{node_id[:12]}]"

        sorted_edges = sorted(
            [e for e in sg.edges if e.first_seen],
            key=lambda e: e.first_seen,
        )

        lines = ["BEHAVIOURS (chronological):"]
        for e in sorted_edges:
            parts = [f"  {e.first_seen}  {e.rel_type}"]
            parts.append(f"    {_resolve(e.src_id)} → {_resolve(e.dst_id)}")
            if e.count > 1:
                parts.append(f"    ×{e.count} occurrences  last={e.last_seen}")
            if e.techniques:
                parts.append(f"    techniques: {', '.join(e.techniques)}")
            if e.tactics:
                parts.append(f"    tactics   : {', '.join(e.tactics)}")
            if e.extra:
                clean = {k: v for k, v in e.extra.items() if v}
                if clean:
                    parts.append(f"    extra     : {json.dumps(clean)}")
            lines.append("\n".join(parts))

        return "\n".join(lines)

    # ── SECTION 5: GAPS ───────────────────────────────────────────────────────
    # Ghost guids only. Inferred binaries removed — parent_image on a ghost
    # template is a guess from process creation events, not observed telemetry.

    def _s_gaps(self, sg: SubgraphContext) -> str:
        if not sg.has_ghost_parents:
            return ""
        ghost_guids = [i.guid for i in sg.instances if i.ghost]
        lines = ["VISIBILITY GAPS (ghost — spawned children but never directly observed):"]
        for g in ghost_guids:
            lines.append(f"  guid={g}")
        return "\n".join(lines)

    # ── SECTION 6: PREVIOUS ───────────────────────────────────────────────────

    def _s_previous(self, case: InvestigationCase) -> str:
        if not case.previous_finding:
            return ""
        pf = case.previous_finding
        lines = [
            "PREVIOUS FINDING (graph has new edges — re-evaluate):",
            f"  verdict={pf.verdict}  severity={pf.severity}",
        ]
        if pf.mitre_techniques:
            lines.append(f"  techniques: {', '.join(pf.mitre_techniques)}")
        if pf.narrative:
            lines.append(f"  summary: {pf.narrative[:250]}")
        return "\n".join(lines)

    # ── SECTION 7: TASK ───────────────────────────────────────────────────────

    def _s_task(self) -> str:
        return """TASK:
You are a senior threat analyst. Analyse this scored Windows Sysmon process graph.
Produce a structured attack summary. Your output goes directly to a responder LLM
that will generate containment actions — give it everything it needs, nothing extra.

SCORING:
  ≥10 = malicious   5-9 = highly suspicious   1-5 = investigate   0 = context only

HOW TO READ:
  - Cross-reference tmpl= short hashes between PROCESS TREE and PROCESS IDENTITIES.
  - BEHAVIOURS is the attack timeline — read it chronologically.
  - techniques/tactics on edges come from Sigma rules — treat them as ground truth.
  - count on an edge = how many times that action occurred (high count = beaconing,
    spray, or enumeration — always call this out in attack_chain).
  - [MISSING:…] = process appeared in an edge but could not be fetched — note as gap.

Return ONLY a JSON object inside <analyst> tags. Nothing outside.

<analyst>
{
  "verdict":    "MALICIOUS | SUSPICIOUS | BENIGN",
  "severity":   "CRITICAL | HIGH | MEDIUM | LOW",
  "confidence": "HIGH | MEDIUM | LOW",
  "attack_name": "<threat family + key technique, specific — e.g. 'Cobalt Strike beacon via PowerShell IEX cradle'>",

  "summary": "<3 sentences: (1) what the attack is, (2) how it unfolded referencing actual image names and guids, (3) current state and impact>",
  "confidence_note": "<what telemetry is missing that limits confidence, or null>",

  "mitre_techniques": ["T1059.001"],
  "mitre_tactics":    ["execution"],

  "attack_chain": [
    {
      "step":      1,
      "image":     "<image.exe>",
      "guid":      "<full guid>",
      "action":    "<rel_type — CREATED | INJECTED_THREAD | CREATED_FILE | CONNECTED | QUERIED_DNS | MODIFIED_REGISTRY | …>",
      "target":    "<child image (guid=…) | C:\\path\\file | 1.2.3.4:4444 | evil.com | HKLM\\…>",
      "technique": "<T####.### or null>",
      "tactic":    "<tactic name or null>",
      "count":     1,
      "note":      "<one sentence: why this step matters — call out high counts, lateral moves, drops>"
    }
  ],

  "processes": [
    {
      "guid":  "<full guid>",
      "image": "<image path>",
      "pid":   null,
      "alive": false,
      "score": 0,
      "role":  "patient_zero | c2_beacon | injector | injected | dropper | lateral | suspicious"
    }
  ],

  "iocs": [
    {
      "type":    "ip | domain | hash | process_name",
      "value":   "<the indicator>",
      "context": "<one sentence: what this IOC did>"
    }
  ],

  "files": [
    {
      "path":    "<absolute path>",
      "event":   "created | modified | deleted | timestomped | ads",
      "context": "<one sentence: what this file is>"
    }
  ],

  "identities": ["<windows username>"],

  "gaps": [
    {
      "guid":        "<ghost or missing guid>",
      "implication": "<what this gap hides about the attack>"
    }
  ]
}
</analyst>

RULES:
- Every guid must exist in PROCESS TREE.
- Every file/IP/domain must appear in BEHAVIOURS or IDENTITIES.
- attack_chain must be strictly chronological, one entry per edge/event.
- High-count edges (×N) must appear in attack_chain with the count in the note.
- summary must reference actual image names and short guids — not generic descriptions.
- Empty [] is valid. Never null for arrays.
- No text, markdown, or comments outside <analyst></analyst>."""

    # ── LLM CALL ──────────────────────────────────────────────────────────────

    def _call_llm(self, prompt: str) -> str:
        filename = f"logs/analyst_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.log"
        #with open(filename, "w", encoding="utf-8") as f:
        #    f.write(prompt)
        print(f"[Analyst] prompt → {filename}  ({len(prompt)} chars)")

        # response = _client.messages.create(
        #     model      = MODEL,
        #     max_tokens = 2000,
        #     system     = (
        #         "You are an expert EDR threat analyst. You analyse Sysmon telemetry "
        #         "as scored process graphs. Be precise — base findings strictly on "
        #         "provided evidence. Output a single JSON object inside <analyst> tags."
        #     ),
        #     messages=[{"role": "user", "content": prompt}],
        # )
        # return response.content[0].text

        return (
            '<analyst>\n'
            '{\n'
            '  "verdict": "SUSPICIOUS", "severity": "MEDIUM", "confidence": "LOW",\n'
            '  "attack_name": "API disabled — placeholder",\n'
            '  "summary": "API disabled.",\n'
            '  "confidence_note": "API disabled.",\n'
            '  "mitre_techniques": [], "mitre_tactics": [],\n'
            '  "attack_chain": [], "processes": [], "iocs": [],\n'
            '  "files": [], "identities": [], "gaps": []\n'
            '}\n'
            '</analyst>'
        )

    # ── PARSER ────────────────────────────────────────────────────────────────

    def _parse(
        self,
        raw:      str,
        case:     InvestigationCase,
        subgraph: SubgraphContext,
    ) -> AttackSummary:

        match = re.search(r"<analyst>(.*?)</analyst>", raw, re.DOTALL)
        if not match:
            return self._error_summary(case, subgraph, "No <analyst> tags", raw)
        try:
            d: Dict[str, Any] = json.loads(match.group(1).strip())
        except json.JSONDecodeError as exc:
            return self._error_summary(case, subgraph, f"JSON error: {exc}", raw)

        verdict    = d.get("verdict",    "SUSPICIOUS")
        severity   = d.get("severity",   "MEDIUM")
        confidence = d.get("confidence", "LOW")

        if verdict    not in ("MALICIOUS", "SUSPICIOUS", "BENIGN"): verdict    = "SUSPICIOUS"
        if severity   not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"): severity   = "MEDIUM"
        if confidence not in ("HIGH", "MEDIUM", "LOW"):             confidence = "LOW"

        should_respond = (
            verdict in _ALWAYS_RESPOND
            or (verdict in _RESPOND_IF_HIGH and severity in _HIGH_SEVERITIES)
        )

        summary = AttackSummary(
            case_id          = case.case_id,
            anchor_guid      = subgraph.anchor_guid,
            verdict          = verdict,
            severity         = severity,
            confidence       = confidence,
            attack_name      = d.get("attack_name", "Unknown"),
            summary          = d.get("summary", ""),
            confidence_note  = d.get("confidence_note"),
            mitre_techniques = d.get("mitre_techniques", []),
            mitre_tactics    = d.get("mitre_tactics",    []),
            attack_chain     = d.get("attack_chain",     []),
            processes        = d.get("processes",        []),
            iocs             = d.get("iocs",             []),
            files            = d.get("files",            []),
            identities       = d.get("identities",       []),
            gaps             = d.get("gaps",             []),
            should_respond   = should_respond,
            raw_llm_response = raw,
        )

        print(
            f"[Analyst] {summary.attack_name}\n"
            f"  verdict={verdict}  severity={severity}  confidence={confidence}"
            f"  should_respond={should_respond}\n"
            f"  chain={len(summary.attack_chain)} steps  "
            f"procs={len(summary.processes)}  "
            f"iocs={len(summary.iocs)}  "
            f"files={len(summary.files)}"
        )
        return summary

    # ── ERROR ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _error_summary(
        case:     InvestigationCase,
        subgraph: SubgraphContext,
        reason:   str,
        raw:      str = "",
    ) -> AttackSummary:
        return AttackSummary(
            case_id          = case.case_id,
            anchor_guid      = subgraph.anchor_guid,
            verdict          = "SUSPICIOUS",
            severity         = "MEDIUM",
            confidence       = "LOW",
            attack_name      = f"Analyst error: {reason}",
            summary          = reason,
            confidence_note  = None,
            mitre_techniques = [],
            mitre_tactics    = [],
            should_respond   = False,
            raw_llm_response = raw,
        )