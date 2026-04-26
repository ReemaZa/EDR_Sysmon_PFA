"""
analyst_agent.py  —  The Analyst: SubgraphContext → AnalystFinding.

RESPONSIBILITY:
    - Build a structured, information-dense prompt from the subgraph context
    - (Future) Call the Anthropic API with that prompt
    - Parse the structured JSON response into an AnalystFinding
    - Never raise — return a low-confidence SUSPICIOUS finding on any failure

CURRENT STATE:
    The Anthropic API call is configured but NOT executed.
    _call_llm() prints the full prompt to console so the output can be
    inspected and the prompt tuned before live API calls are enabled.
    To enable the real call: uncomment the anthropic block in _call_llm()
    and set the ANTHROPIC_API_KEY environment variable.

PROMPT STRUCTURE:
    Section 1 — PROCESS TREE      (instances sorted anchor-first, score desc)
    Section 2 — BEHAVIOUR EDGES   (sorted by total_score desc)
    Section 3 — CHRONOLOGICAL TIMELINE
    Section 4 — VISIBILITY GAPS   (ghost parents, only when present)
    Section 5 — PREVIOUS FINDING  (only on re-investigation)
    Section 6 — TASK + OUTPUT CONTRACT

OUTPUT CONTRACT:
    LLM must return a single JSON object inside <finding> tags.
    All other text is ignored during parsing.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

from src.detection.l4_llm_detection.l4_models import (
    AnalystFinding,
    InvestigationCase,
    SubgraphContext,
)

# ── API configuration (not yet active) ───────────────────────────────────────
# import anthropic
# MODEL      = "claude-sonnet-4-20250514"
# MAX_TOKENS = 2000
# _client    = anthropic.Anthropic()   # reads ANTHROPIC_API_KEY from env


class AnalystAgent:
    """
    Stateless analyst. Call analyse(case, subgraph) once per investigation.
    Returns an AnalystFinding — never raises.
    """

    def analyse(
        self,
        case:     InvestigationCase,
        subgraph: SubgraphContext,
    ) -> AnalystFinding:
        try:
            prompt  = self._build_prompt(case, subgraph)
            raw     = self._call_llm(prompt)          # prints prompt, returns placeholder
            finding = self._parse_response(raw, case, subgraph)
            return finding
        except Exception as exc:
            print(f"[Analyst][ERROR] case={case.case_id[:8]}: {exc}")
            return self._error_finding(case, subgraph, str(exc))

    # ── PROMPT BUILDER ────────────────────────────────────────────────────────

    def _build_prompt(
        self,
        case:     InvestigationCase,
        subgraph: SubgraphContext,
    ) -> str:

        sections = [
            self._section_process_tree(subgraph),
            self._section_behaviour_edges(subgraph),
            self._section_timeline(subgraph),
            self._section_ghost_flags(subgraph),
        ]
        context_block = "\n\n".join(s for s in sections if s)

        # Include previous finding on re-investigation
        previous_block = ""
        if case.previous_finding:
            pf = case.previous_finding
            previous_block = (
                "\n\nPREVIOUS INVESTIGATION FINDING (same component, earlier run):\n"
                f"  Verdict:    {pf.verdict}\n"
                f"  Severity:   {pf.severity}\n"
                f"  Techniques: {', '.join(pf.mitre_techniques)}\n"
                f"  Narrative:  {pf.narrative[:400]}\n"
                "\nThe graph has been updated since this finding. "
                "Re-evaluate with the latest evidence.\n"
            )

        task_block = f"""
CASE ID:               {case.case_id}
ANCHOR PROCESS GUID:   {subgraph.anchor_guid}
ANCHOR SCORE:          {subgraph.anchor_score}
SUBGRAPH SIZE:         {subgraph.total_nodes} nodes,  {subgraph.total_edges} edges

TASK:
You are a senior threat analyst reviewing Sysmon telemetry from a Windows endpoint.
The data above was extracted from a graph-based EDR system. Scores are cumulative
integers from Sigma rule matches (scale 1–4 per rule; higher = more severe).

Return ONLY a JSON object inside <finding> tags. No text outside the tags.

<finding>
{{
  "verdict":               "MALICIOUS" | "SUSPICIOUS" | "BENIGN",
  "severity":              "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "confidence":            "HIGH" | "MEDIUM" | "LOW",
  "mitre_techniques":      ["T1003.001", ...],
  "mitre_tactics":         ["credential-access", ...],
  "patient_zero_guid":     "<guid of first malicious process, or null>",
  "active_guid":           "<guid of process currently causing damage, or null>",
  "narrative":             "<2–4 sentence attack description>",
  "false_positive_reason": "<explanation if BENIGN, else null>"
}}
</finding>

Rules:
- Use only the data provided above. Do not invent process names or file paths.
- MITRE techniques must be ATT&CK format (e.g. T1003.001).
- patient_zero_guid and active_guid must be GUIDs listed in the process tree.
- If a parent is a ghost (never observed), flag this as a visibility gap in the narrative.
- If confidence is LOW, explain why in the narrative.
"""

        return context_block + previous_block + task_block

    # ── PROMPT SECTIONS ───────────────────────────────────────────────────────

    def _section_process_tree(self, sg: SubgraphContext) -> str:
        if not sg.instances:
            return ""

        lines = ["=" * 80,
                 "PROCESS TREE:",
                 "=" * 80]

        sorted_inst = sorted(
            sg.instances,
            key=lambda i: (0 if i.guid == sg.anchor_guid else 1, -i.score),
        )

        for inst in sorted_inst:
            # ← fetch template to get image/cmdline/user
            tmpl = sg.templates.get(inst.template_hash or "")

            tags  = ""
            tags += "  ← ANCHOR"   if inst.guid == sg.anchor_guid else ""
            tags += "  [GHOST]"    if inst.ghost else ""
            tags += "  [ALIVE]"    if inst.alive else "  [TERMINATED]"

            lines.append(
                f"\n  GUID:         {inst.guid}{tags}\n"
                f"  Image:        {(tmpl.image        if tmpl else None) or '(unknown)'}\n"
                f"  Parent Image: {(tmpl.parent_image if tmpl else None) or '(unknown)'}\n"
                f"  Command Line: {(tmpl.cmdline       if tmpl else None) or '(unknown)'}\n"
                f"  User:         {(tmpl.user          if tmpl else None) or '(unknown)'}\n"
                f"  Score:        {inst.score}\n"
                f"  Start:        {inst.start_time    or 'unknown'}\n"
                f"  End:          {inst.end_time       or 'N/A'}"
            )
        return "\n".join(lines)
    def _section_behaviour_edges(self, sg: SubgraphContext) -> str:
            if not sg.edges:
                return ""

            lines = ["=" * 80,
                     "BEHAVIOUR EDGES (sorted by score, highest first):",
                     "=" * 80]

            for edge in sorted(sg.edges, key=lambda e: -e.total_score):
                # Resolve destination display name
                dst_display = edge.dst_id
                for art in sg.artifacts:
                    if art.id == edge.dst_id:
                        dst_display = f"{art.label}:{art.id}"
                        break

                extra_str = ""
                if edge.extra:
                    relevant = {k: v for k, v in edge.extra.items() if v}
                    if relevant:
                        extra_str = f"  Extra:        {json.dumps(relevant)}\n"

                lines.append(
                    f"\n  {edge.rel_type}:  {edge.src_id}  →  {dst_display}\n"
                    f"  Score:        {edge.total_score}  "
                    f"(seen {edge.count}x,  first={edge.first_seen},  last={edge.last_seen})\n"
                    f"  Techniques:   {', '.join(edge.techniques)  or 'none'}\n"
                    f"  Tactics:      {', '.join(edge.tactics)     or 'none'}\n"
                    f"  Sigma IDs:    {', '.join(edge.finding_ids) or 'none'}\n"
                    f"{extra_str}"
                )
            return "\n".join(lines)

    def _section_timeline(self, sg: SubgraphContext) -> str:
        if not sg.timeline:
            return ""

        lines = ["=" * 80,
                 "CHRONOLOGICAL TIMELINE:",
                 "=" * 80]

        for entry in sg.timeline:
            techs = f"  [{entry['techniques']}]" if entry.get("techniques") else ""
            dst   = f"  →  {entry['dst']}"       if entry.get("dst")        else ""
            lines.append(
                f"  {entry['timestamp']}  "
                f"{entry['rel_type']:<22s}  "
                f"{entry['src']}{dst}{techs}"
            )
        return "\n".join(lines)

    def _section_ghost_flags(self, sg: SubgraphContext) -> str:
        if not sg.has_ghost_parents:
            return ""
        ghost_guids = [i.guid for i in sg.instances if i.ghost]
        return (
            "=" * 80 + "\n"
            "VISIBILITY GAPS — GHOST PARENTS (never directly observed):\n"
            "=" * 80 + "\n"
            + "\n".join(f"  {g}" for g in ghost_guids)
            + "\nThese processes spawned observed children but generated no detectable"
              " events. Their identity is inferred from child template parent_image fields."
        )

    # ── LLM CALL (PROMPT-PRINT MODE) ──────────────────────────────────────────

    def _call_llm(self, prompt: str) -> str:
        """
        Currently: print the prompt to console and return a placeholder response.
        To enable the real API call:
          1. Set ANTHROPIC_API_KEY in your environment
          2. Uncomment the anthropic block below
          3. Remove or comment out the print + placeholder return
        """
        print("\n" + "█" * 80)
        print("[Analyst] PROMPT THAT WILL BE SENT TO LLM:")
        print("█" * 80)
        print(prompt)
        
        print("█" * 80 + "\n")

        # ── REAL API CALL (disabled until ready) ──────────────────────────
        # response = _client.messages.create(
        #     model      = MODEL,
        #     max_tokens = MAX_TOKENS,
        #     system     = (
        #         "You are an expert cybersecurity threat analyst specialising in "
        #         "endpoint detection and response. You analyse Sysmon telemetry "
        #         "represented as scored process graphs. You are precise, concise, "
        #         "and base findings strictly on provided evidence. "
        #         "You always respond with a single JSON object inside <finding> tags."
        #     ),
        #     messages=[{"role": "user", "content": prompt}],
        # )
        # return response.content[0].text
        # ─────────────────────────────────────────────────────────────────

        # Placeholder — produces a SUSPICIOUS/MEDIUM finding so the queue
        # moves forward and you can see the end-to-end flow.
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
            '  "narrative": "LLM API call is disabled. Prompt printed to console for review.",\n'
            '  "false_positive_reason": null\n'
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

        # Safe defaults for all fields
        verdict    = data.get("verdict",    "SUSPICIOUS")
        severity   = data.get("severity",   "MEDIUM")
        confidence = data.get("confidence", "LOW")

        if verdict    not in ("MALICIOUS", "SUSPICIOUS", "BENIGN"):    verdict    = "SUSPICIOUS"
        if severity   not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):    severity   = "MEDIUM"
        if confidence not in ("HIGH", "MEDIUM", "LOW"):                confidence = "LOW"

        finding = AnalystFinding(
            case_id               = case.case_id,
            anchor_guid           = subgraph.anchor_guid,
            severity              = severity,
            confidence            = confidence,
            verdict               = verdict,
            narrative             = data.get("narrative", "No narrative provided."),
            mitre_techniques      = data.get("mitre_techniques", []),
            mitre_tactics         = data.get("mitre_tactics",    []),
            patient_zero_guid     = data.get("patient_zero_guid"),
            active_guid           = data.get("active_guid"),
            false_positive_reason = data.get("false_positive_reason"),
            raw_llm_response      = raw,
        )

        print(
            f"[Analyst] verdict={finding.verdict}  "
            f"severity={finding.severity}  "
            f"confidence={finding.confidence}\n"
            f"  narrative: {finding.narrative[:120]}"
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