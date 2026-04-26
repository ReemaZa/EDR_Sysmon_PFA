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
    KEPT    extra       — port, protocol, access_mask, etc. operatively relevant
    REMOVED finding_ids — internal Sigma rule IDs, LLM cannot use them

WHAT WAS REMOVED from templates:
    REMOVED seen_count / total_score / first_seen / last_seen — prevalence noise
    REMOVED full template_hash — 12-char prefix is enough for cross-referencing
    REMOVED ghost inferred_binaries — guessed parent images mislead analysis
"""
from __future__ import annotations

from datetime import datetime
import json
from typing import Any, Dict, List, Optional

from google.ai.generativelanguage import Schema, Type

from src.detection.l4_llm_detection.l4_models import (
    InvestigationCase,
    SubgraphContext,
    AttackSummary
)

_ALWAYS_RESPOND  = {"MALICIOUS"}
_RESPOND_IF_HIGH = {"SUSPICIOUS"}
_HIGH_SEVERITIES = {"CRITICAL", "HIGH"}

import google.generativeai as genai

# Gemini configuration
GEMINI_API_KEY = "AIzaSyBROiWkb-q3P7op_Lxjyk6Nmda1CFoen48"
MODEL_NAME     = "gemini-2.5-flash"

genai.configure(api_key=GEMINI_API_KEY)


# ── STRUCTURED OUTPUT SCHEMA ──────────────────────────────────────────────────

def get_response_schema() -> Schema:
    return Schema(
        type=Type.OBJECT,
        properties={

            "verdict":    Schema(type=Type.STRING, enum=["MALICIOUS", "SUSPICIOUS", "BENIGN"]),
            "severity":   Schema(type=Type.STRING, enum=["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
            "confidence": Schema(type=Type.STRING, enum=["HIGH", "MEDIUM", "LOW"]),
            "attack_name":    Schema(type=Type.STRING),
            "summary":        Schema(type=Type.STRING),
            "confidence_note": Schema(type=Type.STRING, nullable=True),
            "mitre_techniques": Schema(type=Type.ARRAY, items=Schema(type=Type.STRING)),
            "mitre_tactics":    Schema(type=Type.ARRAY, items=Schema(type=Type.STRING)),
                        "execution_speed": Schema(
    type=Type.OBJECT,
    nullable=True,
    properties={
        "total_duration_ms":  Schema(type=Type.INTEGER),
        "first_event":        Schema(type=Type.STRING),
        "last_event":         Schema(type=Type.STRING),
        "assessment":         Schema(type=Type.STRING),
    },
    required=["total_duration_ms", "first_event", "last_event", "assessment"],
),
            "attack_chain": Schema(
                type=Type.ARRAY,
                items=Schema(
                    type=Type.OBJECT,
                    properties={
                        "step":      Schema(type=Type.INTEGER),
                        "image":     Schema(type=Type.STRING),
                        "guid":      Schema(type=Type.STRING),
                        "action":    Schema(type=Type.STRING),
                        "target":    Schema(type=Type.STRING),
                        "technique": Schema(type=Type.STRING, nullable=True),
                        "tactic":    Schema(type=Type.STRING, nullable=True),
                        "count":     Schema(type=Type.INTEGER),
                        "duration_ms": Schema(type=Type.INTEGER, nullable=True),
                        "note":      Schema(type=Type.STRING),
                    },
                    required=["step", "image", "guid", "action", "target", "count", "note"],
                )
            ),
            "processes": Schema(
                type=Type.ARRAY,
                items=Schema(
                    type=Type.OBJECT,
                    properties={
                        "guid":  Schema(type=Type.STRING),
                        "image": Schema(type=Type.STRING),
                        "pid":   Schema(type=Type.INTEGER, nullable=True),
                        "alive": Schema(type=Type.BOOLEAN),
                        "score": Schema(type=Type.INTEGER),
                        "role":  Schema(type=Type.STRING),
                    },
                    required=["guid", "image", "alive", "score", "role"],
                )
            ),
            "iocs": Schema(
                type=Type.ARRAY,
                items=Schema(
                    type=Type.OBJECT,
                    properties={
                        "type":    Schema(type=Type.STRING, enum=["ip", "domain", "hash", "process_name"]),
                        "value":   Schema(type=Type.STRING),
                        "context": Schema(type=Type.STRING),
                    },
                    required=["type", "value", "context"],
                )
            ),
            "files": Schema(
                type=Type.ARRAY,
                items=Schema(
                    type=Type.OBJECT,
                    properties={
                        "path":    Schema(type=Type.STRING),
                        "event":   Schema(type=Type.STRING, enum=["created", "modified", "deleted", "timestomped", "ads"]),
                        "context": Schema(type=Type.STRING),
                    },
                    required=["path", "event", "context"],
                )
            ),
            "expected_but_missing": Schema(
    type=Type.ARRAY,
    items=Schema(
        type=Type.OBJECT,
        properties={
            "artifact": Schema(type=Type.STRING),
            "reason":   Schema(type=Type.STRING),
        },
        required=["artifact", "reason"],
    )
),
"noise": Schema(
    type=Type.ARRAY,
    items=Schema(
        type=Type.OBJECT,
        properties={
            "artifact": Schema(type=Type.STRING),
            "reason":   Schema(type=Type.STRING),
        },
        required=["artifact", "reason"],
    )
),
            "identities": Schema(type=Type.ARRAY, items=Schema(type=Type.STRING)),
            "gaps": Schema(
                type=Type.ARRAY,
                items=Schema(
                    type=Type.OBJECT,
                    properties={
                        "guid":        Schema(type=Type.STRING),
                        "implication": Schema(type=Type.STRING),
                    },
                    required=["guid", "implication"],
                )
            ),
        },
        required=[
            "verdict", "severity", "confidence", "attack_name", "summary",
            "mitre_techniques", "mitre_tactics", "attack_chain",
            "processes", "iocs", "files", "identities", "gaps","noise","expected_but_missing","execution_speed"
        ],
    )


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
            self._s_lookup_table(subgraph),   # reference dictionary — always first
            self._s_process_tree(subgraph),
            self._s_behaviours(subgraph),
            self._s_gaps(subgraph),
            self._s_previous(case),
            self._s_task(),
        ]
        return "\n\n".join(s for s in sections if s)

    # ── SECTION 1: HEADER ─────────────────────────────────────────────────────

    def _s_header(self, case: InvestigationCase, sg: SubgraphContext) -> str:
        return (
            #f"CASE: {case.case_id}\n"
            #f"ANCHOR: {sg.anchor_guid}  score={sg.anchor_score}\n"
            f"GRAPH: {len(sg.instances)} processes  "
            f"{len(sg.artifacts)} artifacts  {sg.total_edges} edges"
        )

    # ── SECTION 2: HASH LOOKUP TABLE ──────────────────────────────────────────
    # Single source of truth. Every tmpl= and guid= in the rest of the prompt
    # resolves here. No data is repeated anywhere else.

    def _s_lookup_table(self, sg: SubgraphContext) -> str:
        if not sg.templates:
            return ""

        # reverse map: template_hash → [guid, ...]
        tmpl_to_guids: Dict[str, List[str]] = {}
        for inst in sg.instances:
            if inst.template_hash:
                tmpl_to_guids.setdefault(inst.template_hash, []).append(inst.guid)

        lines = [
            "HASH LOOKUP TABLE:",
            "  Every tmpl= hash in this report maps to one entry below.",
            "  Each guid= under an entry is a live instance of that process identity.",
            "  Resolve any tmpl= or guid= you encounter by looking it up here.",
        ]

        for tmpl in sg.templates.values():
            t_short = tmpl.template_hash[:12]
            guids   = tmpl_to_guids.get(tmpl.template_hash, [])

            # identity line
            parts = [f"  tmpl={t_short}", f"image={tmpl.image or '?'}"]
            if tmpl.parent_image: parts.append(f"spawned-by={tmpl.parent_image}")
            if tmpl.user:         parts.append(f"user={tmpl.user}")
            if tmpl.cmdline:      parts.append(f"cmdline={tmpl.cmdline}")
            lines.append("  |  ".join(parts))

            # one guid per line with score and alive status
            for g in guids:
                inst      = next((i for i in sg.instances if i.guid == g), None)
                alive_tag = "alive" if (inst and inst.alive) else "dead"
                score_val = inst.score if inst else "?"
                lines.append(f"      guid={g}  score={score_val}  [{alive_tag}]")

        return "\n".join(lines)

    # ── SECTION 3: PROCESS TREE ───────────────────────────────────────────────

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
            #if inst.guid == sg.anchor_guid: tags.append("ANCHOR")
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

    # ── SECTION 4: BEHAVIOURS ─────────────────────────────────────────────────

    def _s_behaviours(self, sg: SubgraphContext) -> str:
        if not sg.edges:
            return ""

        inst_map = {i.guid: i for i in sg.instances}
        art_map  = {a.id: a for a in sg.artifacts}

        def _resolve(node_id: str) -> str:
            inst = inst_map.get(node_id)
            if inst:
                t     = sg.templates.get(inst.template_hash or "")
                image = (t.image if t else None) or "parentimage in lookup"
                return f"{image} (guid={node_id})"
            art = art_map.get(node_id)
            if art:
                label = art.extra.get("image") or node_id
                return f"{art.label}:{label}"
            return f"[MISSING:{node_id}]"

        sorted_edges = sorted(
            [e for e in sg.edges if e.first_seen],
            key=lambda e: e.first_seen,
        )

        lines = ["BEHAVIOURS (chronological):"]
        for e in sorted_edges:
            parts = [f"  {e.first_seen} -> {e.last_seen.split()[1]} {e.rel_type}  score={e.total_score}"]
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
  - HASH LOOKUP TABLE is your reference dictionary. Every tmpl= hash and every guid=
    that appears in PROCESS TREE and BEHAVIOURS is defined there. When you see
    tmpl=abc123 or guid=xyz, look it up to get image, cmdline, user, parent, and
    all instances of that process identity.
  - PROCESS TREE shows spawn hierarchy. Resolve tmpl= and guid= via the table.
  - BEHAVIOURS is the attack timeline — read it chronologically. Each edge shows
    image_name (guid=...) so you can immediately see what acted, and look up full
    context in the table if needed.
  - techniques/tactics on edges come from Sigma rules — treat them as ground truth.
  - count on an edge = how many times that action occurred (high count = beaconing,
    spray, or enumeration — always call this out in attack_chain).
  - [MISSING:…] = process appeared in an edge but could not be fetched — note as gap.
  - expected_but_missing: list what you would normally expect to see for this attack
    pattern but did NOT find in the telemetry. Examples: a persistence mechanism
    after a dropper, network C2 after a loader, credential dump after privilege
    escalation. Be specific — name the artifact or behaviour type and why you
    expected it.
  - noise: list any info that appeared in the graph but was
    irrelevant to the attack — explain why each was discarded. This helps the
    responder avoid acting on false positives.
Return ONLY a valid JSON object matching the schema. No extra text.
- BEHAVIOURS timestamps are critical. Compute the duration between first and last
    event in the chain.
    example: Sub-second execution (< 1000ms) = automated stager, not human.
    Always report timestamp and duration_ms per attack_chain step, and summarise..
"""

    # ── LLM CALL ──────────────────────────────────────────────────────────────

    def _call_llm(self, prompt: str) -> Dict[str, Any]:
        filename = f"prompts/prompt_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.log"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(prompt)
        print(f"[Analyst] prompt → {filename}  ({len(prompt)} chars)")

        try:
            model = genai.GenerativeModel(
                MODEL_NAME,
                system_instruction=(
                    "You are an expert EDR threat analyst. You analyse Sysmon telemetry "
                    "as scored process graphs. Be precise — base findings strictly on "
                    "provided evidence. Return a valid JSON object matching the schema."
                )
            )

            response = model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.1,
                    top_p=0.95,
                    max_output_tokens=4096,
                    response_mime_type="application/json",
                    response_schema=get_response_schema(),
                )
            )

            result = json.loads(response.text)

            response_file = f"prompts/response_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            with open(response_file, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            print(f"[Analyst] structured response → {response_file}")

            return result

        except Exception as exc:
            print(f"[Analyst][ERROR] Gemini API call failed: {exc}")
            return self._get_fallback_dict()

    def _get_fallback_dict(self) -> Dict[str, Any]:
        return {
            "verdict":          "SUSPICIOUS",
            "severity":         "MEDIUM",
            "confidence":       "LOW",
            "attack_name":      "Analysis Failed",
            "summary":          "LLM analysis failed. Manual review required.",
            "confidence_note":  "API error prevented analysis",
            "mitre_techniques": [],
            "mitre_tactics":    [],
            "attack_chain":     [],
            "processes":        [],
            "iocs":             [],
            "files":            [],
            "identities":       [],
            "gaps":             [],
        }

    # ── PARSER ────────────────────────────────────────────────────────────────

    def _parse(
        self,
        raw:      Dict[str, Any],
        case:     InvestigationCase,
        subgraph: SubgraphContext,
    ) -> AttackSummary:

        verdict    = raw.get("verdict",    "SUSPICIOUS")
        severity   = raw.get("severity",   "MEDIUM")
        confidence = raw.get("confidence", "LOW")

        if verdict    not in ("MALICIOUS", "SUSPICIOUS", "BENIGN"):   verdict    = "SUSPICIOUS"
        if severity   not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):   severity   = "MEDIUM"
        if confidence not in ("HIGH", "MEDIUM", "LOW"):               confidence = "LOW"

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
            attack_name      = raw.get("attack_name", "Unknown"),
            summary          = raw.get("summary", ""),
            confidence_note  = raw.get("confidence_note"),
            mitre_techniques = raw.get("mitre_techniques", []),
            mitre_tactics    = raw.get("mitre_tactics",    []),
            attack_chain     = raw.get("attack_chain",     []),
            processes        = raw.get("processes",        []),
            iocs             = raw.get("iocs",             []),
            files            = raw.get("files",            []),
            identities       = raw.get("identities",       []),
            gaps             = raw.get("gaps",             []),
            expected_but_missing = raw.get("expected_but_missing", []),
            noise = raw.get("noise",                []),
            should_respond   = should_respond,
            raw_llm_response = json.dumps(raw),
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