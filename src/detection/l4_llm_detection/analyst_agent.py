"""
analyst_agent.py  —  The Analyst: SubgraphContext → AnalystFinding.

PROMPT STRUCTURE:
    Section 1 — HEADER
    Section 2 — PROCESS TREE       (spawn hierarchy, template_hash refs)
    Section 3 — PROCESS IDENTITIES (keyed by template_hash)
    Section 4 — BEHAVIOURS         (ALL edges chronological, no repetition)
    Section 5 — VISIBILITY GAPS    (ghost parents only if present)
    Section 6 — PREVIOUS FINDING   (only on re-investigation)
    Section 7 — TASK + OUTPUT CONTRACT
"""
from __future__ import annotations

from datetime import datetime
import json
import re
from typing import Any, Dict, List, Optional

from src.detection.l4_llm_detection.l4_models import (
    AnalystFinding,
    InvestigationCase,
    SubgraphContext,
)


class AnalystAgent:

    def analyse(self, case: InvestigationCase, subgraph: SubgraphContext) -> AnalystFinding:
        try:
            prompt  = self._build_prompt(case, subgraph)
            raw     = self._call_llm(prompt)
            finding = self._parse_response(raw, case, subgraph)
            return finding
        except Exception as exc:
            print(f"[Analyst][ERROR] case={case.case_id[:8]}: {exc}")
            return self._error_finding(case, subgraph, str(exc))

    # ── PROMPT BUILDER ────────────────────────────────────────────────────────

    def _build_prompt(self, case: InvestigationCase, subgraph: SubgraphContext) -> str:
        sections = [
            self._section_header(case, subgraph),
            self._section_process_tree(subgraph),
            self._section_identities(subgraph),
            self._section_behaviours(subgraph),
            self._section_ghost_flags(subgraph),
            self._section_previous_finding(case),
            self._section_task(),
        ]
        return "\n\n".join(s for s in sections if s)

    # ── SECTIONS ──────────────────────────────────────────────────────────────

    def _section_header(self, case: InvestigationCase, sg: SubgraphContext) -> str:
        return (
            f"CASE: {case.case_id}\n"
            f"ANCHOR: {sg.anchor_guid}  score={sg.anchor_score}\n"
            f"SUBGRAPH: {len(sg.instances)} processes  "
            f"{len(sg.artifacts)} artifacts  {sg.total_edges} edges"
        )

    def _section_process_tree(self, sg: SubgraphContext) -> str:
        """
        Spawn hierarchy only — no behaviour here.
        Each node shows: score, template_hash (key into IDENTITIES), guid, tags.
        template_hash lets the LLM look up the binary identity without repetition.
        """
        if not sg.instances:
            return ""

        inst_map = {i.guid: i for i in sg.instances}
        lines    = ["PROCESS TREE (spawn hierarchy):"]
        lines.append(
            "  format: [score] <template_hash>  guid=<guid>  [tags]"
        )

        def _render(guid: str, depth: int):
            inst = inst_map.get(guid)
            if not inst:
                return
            prefix  = "  " * depth + ("└─ " if depth > 0 else "")
            tags    = []
            if inst.guid == sg.anchor_guid: tags.append("ANCHOR")
            if inst.ghost:                  tags.append("GHOST")
            if not inst.alive:              tags.append("TERMINATED")
            tag_str   = f"  [{', '.join(tags)}]" if tags else ""
            t_hash    = inst.template_hash or "no-template"
            # Short hash for readability, full hash in identities section
            t_short   = t_hash[:12] if t_hash != "no-template" else "no-template"
            lines.append(
                f"{prefix}[score={inst.score}] tmpl={t_short}  "
                f"guid={inst.guid}{tag_str}"
            )
            for child_guid in sg.process_tree.get(guid, []):
                _render(child_guid, depth + 1)

        for root in sg.tree_roots:
            _render(root, 0)

        return "\n".join(lines)

    def _section_identities(self, sg: SubgraphContext) -> str:
        """
        One entry per template_hash — the full identity of each unique binary.
        LLM cross-references tmpl= from the tree to understand what each process is.
        Empty fields omitted.
        """
        if not sg.templates:
            return ""

        lines = ["PROCESS IDENTITIES (keyed by template_hash):"]
        for tmpl in sg.templates.values():
            # Full hash here so LLM can match tmpl= short prefix from tree
            lines.append(f"\n  tmpl={tmpl.template_hash}")
            lines.append(f"    image  : {tmpl.image or '?'}")
            if tmpl.parent_image: lines.append(f"    parent : {tmpl.parent_image}")
            if tmpl.cmdline:      lines.append(f"    cmdline: {tmpl.cmdline}")
            if tmpl.user:         lines.append(f"    user   : {tmpl.user}")
            if tmpl.seen_count:   lines.append(
                f"    seen   : {tmpl.seen_count}x  "
                f"score={tmpl.total_score}  "
                f"window={tmpl.first_seen} → {tmpl.last_seen}"
            )

        return "\n".join(lines)

    def _section_behaviours(self, sg: SubgraphContext) -> str:
        """
        ALL edges in chronological order — one place, no repetition.
        Includes: CREATED, ACCESSED_MEMORY, INJECTED_THREAD, TAMPERED,
                  CREATED_FILE, MODIFIED_REGISTRY, CONNECTED, QUERIED_DNS,
                  LOADED_DRIVER, LOADED_IMAGE, TIMESTOMPED, WROTE_ADS, DELETED.
        src/dst resolved to tmpl= short hash where possible, artifact label otherwise.
        Empty fields omitted entirely.
        """
        if not sg.edges:
            return ""

        inst_map = {i.guid: i for i in sg.instances}
        art_map  = {a.id: a for a in sg.artifacts}

        def _resolve(node_id: str) -> str:
            """Resolve a node id to tmpl=short or artifact label."""
            inst = inst_map.get(node_id)
            if inst and inst.template_hash:
                return f"tmpl={inst.template_hash[:12]}(guid={node_id}…)"
            art = art_map.get(node_id)
            if art:
                return f"{art.label}:{node_id} "
            return node_id

        # Sort all edges chronologically by first_seen
        sorted_edges = sorted(
            [e for e in sg.edges if e.first_seen],
            key=lambda e: e.first_seen,
        )

        lines = ["BEHAVIOURS (all edges, chronological):"]
        for edge in sorted_edges:
            src = _resolve(edge.src_id)
            dst = _resolve(edge.dst_id)

            parts = [
                f"  {edge.first_seen}  {edge.rel_type}",
                f"    {src} → {dst}",
            ]
            if edge.count > 1:
                parts.append(f"    repeated : {edge.count}x  last={edge.last_seen}")
            if edge.techniques:
                parts.append(f"    techniques: {', '.join(edge.techniques)}")
            if edge.tactics:
                parts.append(f"    tactics   : {', '.join(edge.tactics)}")
            if edge.finding_ids:
                parts.append(f"    sigma_ids : {', '.join(edge.finding_ids)}")
            if edge.extra:
                clean = {k: v for k, v in edge.extra.items() if v}
                if clean:
                    parts.append(f"    extra     : {json.dumps(clean)}")

            lines.append("\n".join(parts))

        return "\n".join(lines)

    def _section_ghost_flags(self, sg: SubgraphContext) -> str:
        if not sg.has_ghost_parents:
            return ""

        ghost_guids = [i.guid for i in sg.instances if i.ghost]
        inferred    = set()
        for i in sg.instances:
            if not i.ghost:
                tmpl = sg.templates.get(i.template_hash or "")
                if tmpl and tmpl.parent_image:
                    inferred.add(tmpl.parent_image)

        lines = [
            "VISIBILITY GAPS (ghost parents — spawned children but never observed):"
        ]
        for g in ghost_guids:
            lines.append(f"  guid={g}")
        if inferred:
            lines.append(f"  inferred binaries: {', '.join(inferred)}")

        return "\n".join(lines)

    def _section_previous_finding(self, case: InvestigationCase) -> str:
        if not case.previous_finding:
            return ""
        pf    = case.previous_finding
        lines = [
            "PREVIOUS FINDING (graph updated since — re-evaluate with new evidence):",
            f"  verdict   : {pf.verdict}  severity={pf.severity}",
        ]
        if pf.mitre_techniques:
            lines.append(f"  techniques: {', '.join(pf.mitre_techniques)}")
        if pf.narrative:
            lines.append(f"  narrative : {pf.narrative[:300]}")
        return "\n".join(lines)

    def _section_task(self) -> str:
        return """TASK:
You are a senior threat analyst reviewing Sysmon telemetry from a Windows EDR system.
Scores are cumulative integers from Sigma rule matches (1–4 per rule; higher = more severe).
Cross-reference tmpl= hashes from the process tree with PROCESS IDENTITIES to understand
what each process is. All behaviours are in chronological order in one place.

Determine: attack chain, patient zero, active threat, IOCs, and recommended actions.

Return ONLY a JSON object inside <finding> tags. No text outside the tags.

<finding>
{
  "verdict":               "MALICIOUS" | "SUSPICIOUS" | "BENIGN",
  "severity":              "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "confidence":            "HIGH" | "MEDIUM" | "LOW",
  "mitre_techniques":      ["T1059.001"],
  "mitre_tactics":         ["execution"],
  "patient_zero_guid":     "<guid from process tree or null>",
  "active_guid":           "<guid from process tree or null>",
  "narrative":             "<3-5 sentences: what happened, how, chain, impact>",
  "iocs": {
    "processes": ["suspicious image paths"],
    "ips":       ["malicious IPs to block"],
    "files":     ["malicious file paths"],
    "registry":  ["tampered registry keys"],
    "dns":       ["malicious domains"]
  },
  "recommended_actions": [
    "Kill process guid=<guid>",
    "Block IP <ip>",
    "Isolate host"
  ],
  "false_positive_reason": "<explanation if BENIGN, else null>",
  "confidence_note":       "<explain if LOW confidence, else null>"
}
</finding>

Rules:
- Use ONLY data provided. Never invent process names, IPs, or paths.
- MITRE techniques must be ATT&CK format (T####.###).
- patient_zero_guid and active_guid must be GUIDs present in the process tree.
- iocs and recommended_actions must reference only observed data.
- Ghost parents are visibility gaps — note in narrative.
- Empty arrays [] are valid. Never output null for array fields."""

    # ── LLM CALL ──────────────────────────────────────────────────────────────

    def _call_llm(self, prompt: str) -> str:
        filename = f"logs/prompt_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.log"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(prompt)
        print(f"[Analyst] Prompt saved → {filename}  ({len(prompt)} chars)")

        # ── REAL API CALL ──────────────────────────────────────────────
        # response = _client.messages.create(
        #     model      = MODEL,
        #     max_tokens = MAX_TOKENS,
        #     system     = (
        #         "You are an expert EDR threat analyst. You analyse Sysmon telemetry "
        #         "represented as scored process graphs. You are precise and base findings "
        #         "strictly on provided evidence. "
        #         "Respond with a single JSON object inside <finding> tags."
        #     ),
        #     messages=[{"role": "user", "content": prompt}],
        # )
        # return response.content[0].text
        # ──────────────────────────────────────────────────────────────

        return (
            '<finding>\n'
            '{\n'
            '  "verdict": "SUSPICIOUS",\n'
            '  "severity": "MEDIUM",\n'
            '  "confidence": "LOW",\n'
            '  "mitre_techniques": [],\n'
            '  "mitre_tactics": [],\n'
            '  "patient_zero_guid": null,\n'
            '  "active_guid": null,\n'
            '  "narrative": "LLM API call is disabled.",\n'
            '  "iocs": {"processes": [], "ips": [], "files": [], "registry": [], "dns": []},\n'
            '  "recommended_actions": [],\n'
            '  "false_positive_reason": null,\n'
            '  "confidence_note": "Placeholder — API disabled."\n'
            '}\n'
            '</finding>'
        )

    # ── RESPONSE PARSER ───────────────────────────────────────────────────────

    def _parse_response(
        self,
        raw:      str,
        case:     InvestigationCase,
        subgraph: SubgraphContext,
    ) -> AnalystFinding:

        match = re.search(r"<finding>(.*?)</finding>", raw, re.DOTALL)
        if not match:
            return self._error_finding(case, subgraph,
                                       "No <finding> tags in response", raw)
        try:
            data: Dict[str, Any] = json.loads(match.group(1).strip())
        except json.JSONDecodeError as exc:
            return self._error_finding(case, subgraph,
                                       f"JSON parse failed: {exc}", raw)

        verdict    = data.get("verdict",    "SUSPICIOUS")
        severity   = data.get("severity",   "MEDIUM")
        confidence = data.get("confidence", "LOW")

        if verdict    not in ("MALICIOUS", "SUSPICIOUS", "BENIGN"): verdict    = "SUSPICIOUS"
        if severity   not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"): severity   = "MEDIUM"
        if confidence not in ("HIGH", "MEDIUM", "LOW"):             confidence = "LOW"

        narrative = data.get("narrative", "No narrative provided.")
        if data.get("confidence_note"):
            narrative += f" [{data['confidence_note']}]"

        finding = AnalystFinding(
            case_id               = case.case_id,
            anchor_guid           = subgraph.anchor_guid,
            severity              = severity,
            confidence            = confidence,
            verdict               = verdict,
            narrative             = narrative,
            mitre_techniques      = data.get("mitre_techniques", []),
            mitre_tactics         = data.get("mitre_tactics",    []),
            patient_zero_guid     = data.get("patient_zero_guid"),
            active_guid           = data.get("active_guid"),
            false_positive_reason = data.get("false_positive_reason"),
            raw_llm_response      = raw,
        )

        print(
            f"[Analyst] verdict={finding.verdict}  "
            f"severity={finding.severity}  confidence={finding.confidence}\n"
            f"  iocs   : {data.get('iocs')}\n"
            f"  actions: {data.get('recommended_actions')}\n"
            f"  narrative: {finding.narrative[:150]}"
        )
        return finding

    # ── ERROR FINDING ─────────────────────────────────────────────────────────

    @staticmethod
    def _error_finding(
        case:     InvestigationCase,
        subgraph: SubgraphContext,
        reason:   str,
        raw:      str = "",
    ) -> AnalystFinding:
        return AnalystFinding(
            case_id               = case.case_id,
            anchor_guid           = subgraph.anchor_guid,
            severity              = "MEDIUM",
            confidence            = "LOW",
            verdict               = "SUSPICIOUS",
            narrative             = f"Analyst error: {reason}",
            mitre_techniques      = [],
            mitre_tactics         = [],
            patient_zero_guid     = None,
            active_guid           = None,
            false_positive_reason = None,
            raw_llm_response      = raw,
        )