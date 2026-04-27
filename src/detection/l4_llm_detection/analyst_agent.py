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
from src.detection.l4_llm_detection.l4_models import (
    InvestigationCase,
    SubgraphContext,
    ResponderOutput,       # ← your new output model (add this to l4_models too)
)


import google.generativeai as genai

GEMINI_API_KEY = "AIzaSyBROiWkb-q3P7op_Lxjyk6Nmda1CFoen48"
MODEL_NAME     = "gemini-3.1-flash-lite-preview"

genai.configure(api_key=GEMINI_API_KEY)


# ── STRUCTURED OUTPUT SCHEMA ──────────────────────────────────────────────────

def get_response_schema() -> "Schema":
    from google.ai.generativelanguage import Schema, Type

    action_schema = Schema(
        type=Type.OBJECT,
        properties={
            "id":           Schema(type=Type.STRING),
            "priority":     Schema(type=Type.INTEGER),
            "type":         Schema(type=Type.STRING, enum=[
                                "process_termination", "blacklist",
                                "file_quarantine", "file_deletion",
                                "alert", "BLOCK_IP", "BLOCK_DOMAIN",
                            ]),
            "target_type":  Schema(type=Type.STRING, enum=[
                                "guid", "tmpl", "file",
                                "ip", "domain", "registry",
                            ]),
            "target_value": Schema(type=Type.STRING),
            "scope":        Schema(type=Type.STRING, enum=[
                                "instance", "all_children",
                                "all_connected", "template",
                            ]),
            "reason":       Schema(type=Type.STRING),
        },
        required=["id", "priority", "type", "target_type", "target_value", "scope", "reason"],
    )

  
    

    return Schema(
        type=Type.OBJECT,
        properties={
            "verdict":           Schema(type=Type.STRING, enum=["MALICIOUS", "SUSPICIOUS","BENIGN-CONTEXT"]),
            "actions":           Schema(type=Type.ARRAY, items=action_schema),
         
        },
        required=["verdict", "actions"],
    )


# ══════════════════════════════════════════════════════════════════════════════

class AnalystAgent:
    # ── PARSER ────────────────────────────────────────────────────────────────

    def _parse(
        self,
        raw:      Dict[str, Any],
        case:     InvestigationCase,
        subgraph: SubgraphContext,
    ) -> ResponderOutput:

        verdict = raw.get("verdict", "SUSPICIOUS")
        if verdict not in ("MALICIOUS", "SUSPICIOUS","BENIGN-CONTEXT"):
            verdict = "SUSPICIOUS"

        result = ResponderOutput(
            case_id           = case.case_id,
            anchor_guid       = subgraph.anchor_guid,
            analysis_id       = case.case_id,
            verdict           = verdict,
            actions           = raw.get("actions",           []),
        
            raw_llm_response  = json.dumps(raw),
        )

        print(
            f"[Responder] verdict={verdict}  "
            f"actions={len(result.actions)}  "
         
        )
        return result

    def analyse(
        self,
        case:     InvestigationCase,
        subgraph: SubgraphContext,
    ) -> ResponderOutput:
        try:
            prompt  = self._build_prompt(case, subgraph)
            raw     = self._call_llm(prompt)
            summary = self._parse(raw, case, subgraph)
            return summary
        except Exception as exc:
            print(f"[Responder][ERROR] case={case.case_id[:8]}: {exc}")
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
                parts.append(f"    ×{e.count} occurrences  ")
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
        lines = ["VISIBILITY GAPS (ghost — parentimage from the lookuptable- score=0):"]
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
You are a senior threat analyst and SOC responder. Analyse this scored Windows Sysmon
process graph and produce machine-executable containment actions and graph annotations.

SCORING:
  ≥10 = fired on more than 3 Sigma rules
  5-9 = fired on more than 1 Sigma rule
  1-4 = fired on one or more low-confidence Sigma rules
    0 = no Sigma rule fired — structural context only

HOW TO READ THE GRAPH:
  - HASH LOOKUP TABLE: resolve every tmpl= and guid= here to get image/cmdline/user/parent.
  - PROCESS TREE: spawn hierarchy. Resolve via table.
  - BEHAVIOURS: attack timeline, read chronologically. techniques/tactics are Sigma ground truth.
  - count > 1 on an edge = beaconing, spray, or enumeration — always flag in attack_chain.
  - [GHOST:guid] = never directly observed. State unknown only — assert nothing.
  - [MISSING:guid] = could not be fetched — note as gap.

ACTION SCOPES (apply strictly):
  scope=instance       → act on this guid only.
  scope=all_children   → this guid + every CHILD_OF descendant recursively.
  scope=all_connected  → terminate any process connected to this ip/domain + perimeter block.
  scope=template       → kill all live instances of this tmpl hash + block future spawns.


"""

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
                    "You are a senior threat analyst and SOC responder. You analyse Sysmon "
                    "telemetry as scored process graphs and produce containment actions and "
                    "graph annotations. Be precise — base every field strictly on evidence "
                    "present in the prompt. Never invent targets or unobserved processes. "
                    "Return a valid JSON object matching the schema."
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
            "verdict":           "SUSPICIOUS",
            "actions":           [],
          
        }

    # ── ERROR ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _error_summary(
        case:     InvestigationCase,
        subgraph: SubgraphContext,
        reason:   str,
        raw:      str = "",
    ) -> ResponderOutput:
        return ResponderOutput(
            case_id           = case.case_id,
            anchor_guid       = subgraph.anchor_guid,
            analysis_id       = case.case_id,
            verdict           = "SUSPICIOUS",
            actions           = [],
        
            raw_llm_response  = raw,
        )