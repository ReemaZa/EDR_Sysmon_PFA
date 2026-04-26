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

GEMINI_API_KEY = "AIzaSyBROiWkb-q3P7op_Lxjyk6Nmda1CFoen48"
MODEL_NAME     = "gemini-3.1-flash-lite-preview"

genai.configure(api_key=GEMINI_API_KEY)


# ── STRUCTURED OUTPUT SCHEMA ──────────────────────────────────────────────────

def get_response_schema() -> Schema:
    return Schema(
        type=Type.OBJECT,
        properties={
            "verdict":         Schema(type=Type.STRING, enum=["MALICIOUS", "SUSPICIOUS", "BENIGN"]),
            "severity":        Schema(type=Type.STRING, enum=["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
            "confidence":      Schema(type=Type.STRING, enum=["HIGH", "MEDIUM", "LOW"]),
            "attack_name":     Schema(type=Type.STRING),
            "summary":         Schema(type=Type.STRING),
            "confidence_note": Schema(type=Type.STRING, nullable=True),
            "mitre_techniques": Schema(type=Type.ARRAY, items=Schema(type=Type.STRING)),
            "mitre_tactics":    Schema(type=Type.ARRAY, items=Schema(type=Type.STRING)),
            "execution_speed": Schema(
                type=Type.OBJECT,
                nullable=True,
                properties={
                    "total_duration_ms": Schema(type=Type.INTEGER),
                    "first_event":       Schema(type=Type.STRING),
                    "last_event":        Schema(type=Type.STRING),
                    "assessment":        Schema(type=Type.STRING),
                },
                required=["total_duration_ms", "first_event", "last_event", "assessment"],
            ),
            "attack_chain": Schema(
                type=Type.ARRAY,
                items=Schema(
                    type=Type.OBJECT,
                    properties={
                        "step":        Schema(type=Type.INTEGER),
                        "image":       Schema(type=Type.STRING),
                        "guid":        Schema(type=Type.STRING),
                        "action":      Schema(type=Type.STRING),
                        "target":      Schema(type=Type.STRING),
                        "technique":   Schema(type=Type.STRING, nullable=True),
                        "tactic":      Schema(type=Type.STRING, nullable=True),
                        "count":       Schema(type=Type.INTEGER),
                        "timestamp":   Schema(type=Type.STRING, nullable=True),
                        "duration_ms": Schema(type=Type.INTEGER, nullable=True),
                        "note":        Schema(type=Type.STRING),
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
                        "alive": Schema(type=Type.BOOLEAN, nullable=True),
                        "score": Schema(type=Type.INTEGER),
                        "role":  Schema(type=Type.STRING),
                        "kill_priority": Schema(type=Type.INTEGER),
                    },
                    required=["guid", "image", "alive", "score", "role","kill_priority"],
                )
            ),
            "iocs": Schema(
                type=Type.ARRAY,
                items=Schema(
                    type=Type.OBJECT,
                    properties={
                        "type": Schema(type=Type.STRING, enum=[
                            "ip", "domain", "hash",
                            "process_name", "cmdline_pattern",
                            "file_path", "registry_key",
                            "driver", "dns_query", "user_account",
                        ]),
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
                        "event":   Schema(type=Type.STRING, enum=[
                            "created", "modified", "deleted", "timestomped", "ads"
                        ]),
                        "context": Schema(type=Type.STRING),
                    },
                    required=["path", "event", "context"],
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
        },
        required=[
            "verdict", "severity", "confidence", "attack_name", "summary",
            "mitre_techniques", "mitre_tactics", "execution_speed", "attack_chain",
            "processes", "iocs", "files", "identities", "gaps",
            "expected_but_missing", "noise",
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
            self._s_lookup_table(subgraph),
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
            f"GRAPH: {len(sg.instances)} processes  "
            f"{len(sg.artifacts)} artifacts  {sg.total_edges} edges"
        )

    # ── SECTION 2: HASH LOOKUP TABLE ──────────────────────────────────────────

    def _s_lookup_table(self, sg: SubgraphContext) -> str:
        if not sg.templates:
            return ""

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

            parts = [f"  tmpl={t_short}", f"image={tmpl.image or '?'}"]
            if tmpl.parent_image: parts.append(f"spawned-by={tmpl.parent_image}")
            if tmpl.user:         parts.append(f"user={tmpl.user}")
            if tmpl.cmdline:      parts.append(f"cmdline={self._summarise_cmdline(tmpl.cmdline)}")
            lines.append("  |  ".join(parts))

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
            prefix = "  " * depth + ("└─ " if depth else "")
            tags   = []
            if inst.ghost:      tags.append("GHOST")
            if not inst.alive:  tags.append("dead")
            tag_str = f"  [{','.join(tags)}]" if tags else ""

            t       = sg.templates.get(inst.template_hash or "")
            t_short = (inst.template_hash or "")[:12] or "no-tmpl"

            if inst.ghost or not t:
                lines.append(
                    f"{prefix}[GHOST — not in lookup table]"
                    f"  score={inst.score}  guid={inst.guid}{tag_str}"
                )
            else:
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
                if inst.ghost or not inst.template_hash:
                    return f"[GHOST:{node_id}]"
                t     = sg.templates.get(inst.template_hash)
                image = (t.image if t else None) or "?"
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
            parts = [f"  {e.first_seen} -> {e.last_seen.split()[1] if e.last_seen else '?'} {e.rel_type}  score={e.total_score}"]
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
        lines = ["VISIBILITY GAPS (ghost — spawned children but never directly observed, score=0):"]
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

SCORING (enforce strictly — do not override with pattern recognition):
  ≥10 = MALICIOUS      → verdict must be MALICIOUS
  5-9 = SUSPICIOUS     → verdict must be SUSPICIOUS
  1-4 = investigate    → verdict must be SUSPICIOUS with LOW confidence
    0 = context only   → benign unless part of a confirmed malicious chain
  Use the highest score across all processes and edges to set verdict.
  NEVER set verdict=MALICIOUS unless at least one score ≥ 10.

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
  - [GHOST:guid] = process appeared in an edge or tree but was never observed directly.
    Do NOT assert its image, alive status, or any property — state only that it is unknown.
  - [MISSING:guid] = process appeared in an edge but could not be fetched — note as gap.


PROCESSES:
  List every process in the graph including noise and ghosts.
 - role: be specific and distinct per process — "WinRM session host", "encoded-command stager",
    "nested PowerShell second stage", "shutdown utility", "code-page init (noise)".
  - kill_priority: deepest child in the attack chain = 1, walk up to root.
    Dead processes, noise, and protected system processes (lsass, csrss, winlogon,
    services, smss, wininit, System, PID < 1000) = 0.
    
IOCS — extract only SPECIFIC, HUNTABLE indicators:
  - cmdline_pattern: suspicious flag combinations e.g. "-executionpolicy unrestricted -encodedcommand"
    spawned from a specific parent — this IS a detection rule.
  - user_account: a domain admin account running encoded PowerShell over WinRM is an IOC.
  - ip / domain: any CONNECTED artifact destination.
  - file_path: any CREATED_FILE or WROTE_ADS artifact path.
  - registry_key: any MODIFIED_REGISTRY artifact path.
  - driver: any LOADED_DRIVER artifact.
  - dns_query: any QUERIED_DNS artifact value.
  - hash: any file hash if available.
  - process_name: ONLY when combined with specific parent + user + flag pattern — never alone.
  If the graph has no artifact of a given type, do not invent values.
  If there are no huntable IOCs, return an empty array.

EXECUTION SPEED — compute from first to last BEHAVIOURS timestamp.
  Sub-second = automated. State it plainly.

NOISE — every process or artifact NOT part of the attack chain needs a reason here.
  Don't leave it empty if unused processes exist in the graph.

EXPECTED BUT MISSING — what should logically follow this attack pattern but wasn't observed?
  C2 beacon after stager, persistence after dropper, cred dump after priv-esc, etc.
  This tells the responder where to look next.

Return ONLY a valid JSON object matching the schema. No extra text."""

    # ── CMDLINE SUMMARISER ────────────────────────────────────────────────────

    @staticmethod
    def _summarise_cmdline(cmdline: str, max_len: int = 120) -> str:
        import re
        cleaned = re.sub(
            r'(?i)(-encodedcommand|-enc)\s+[A-Za-z0-9+/=]{20,}',
            r'\1 [BASE64-ENCODED-PAYLOAD]',
            cmdline
        )
        if len(cleaned) <= max_len:
            return cleaned
        return cleaned[:max_len] + "  …[truncated]"

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
                    "as scored process graphs. Be precise — base every field strictly on "
                    "evidence present in the prompt. Never invent values for unobserved "
                    "processes. Return a valid JSON object matching the schema."
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
            "verdict":              "SUSPICIOUS",
            "severity":             "MEDIUM",
            "confidence":           "LOW",
            "attack_name":          "Analysis Failed",
            "summary":              "LLM analysis failed. Manual review required.",
            "confidence_note":      "API error prevented analysis",
            "mitre_techniques":     [],
            "mitre_tactics":        [],
            "execution_speed":      None,
            "attack_chain":         [],
            "processes":            [],
            "iocs":                 [],
            "files":                [],
            "identities":           [],
            "gaps":                 [],
            "expected_but_missing": [],
            "noise":                [],
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

        if verdict    not in ("MALICIOUS", "SUSPICIOUS", "BENIGN"): verdict    = "SUSPICIOUS"
        if severity   not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"): severity   = "MEDIUM"
        if confidence not in ("HIGH", "MEDIUM", "LOW"):             confidence = "LOW"

        should_respond = (
            verdict in _ALWAYS_RESPOND
            or (verdict in _RESPOND_IF_HIGH and severity in _HIGH_SEVERITIES)
        )

        summary = AttackSummary(
            case_id              = case.case_id,
            anchor_guid          = subgraph.anchor_guid,
            verdict              = verdict,
            severity             = severity,
            confidence           = confidence,
            attack_name          = raw.get("attack_name", "Unknown"),
            summary              = raw.get("summary", ""),
            confidence_note      = raw.get("confidence_note"),
            mitre_techniques     = raw.get("mitre_techniques",     []),
            mitre_tactics        = raw.get("mitre_tactics",        []),
            attack_chain         = raw.get("attack_chain",         []),
            processes            = raw.get("processes",            []),
            iocs                 = raw.get("iocs",                 []),
            files                = raw.get("files",                []),
            identities           = raw.get("identities",           []),
            gaps                 = raw.get("gaps",                 []),
            expected_but_missing = raw.get("expected_but_missing", []),
            noise                = raw.get("noise",                []),
            should_respond       = should_respond,
            raw_llm_response     = json.dumps(raw),
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