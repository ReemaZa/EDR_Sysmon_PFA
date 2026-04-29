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

import os
from datetime import datetime
import json
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

from src.detection.l4_llm_detection.l4_models import ResponderOutput
from src.detection.l4_llm_detection.graph_extractor import SubgraphContext

import google.generativeai as genai

# Load environment variables from .env file
load_dotenv()

# Retrieve API key from environment
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
if not GEMINI_API_KEY:
    raise EnvironmentError("[AnalystAgent] GEMINI_API_KEY environment variable is not set.")

MODEL_NAME = "gemini-3.1-flash-lite-preview"

genai.configure(api_key=GEMINI_API_KEY)


# ── STRUCTURED OUTPUT SCHEMA ──────────────────────────────────────────────────

def get_response_schema() -> "Schema":
    from google.ai.generativelanguage import Schema, Type

    action_schema = Schema(
        type=Type.OBJECT,
        properties={
            "id":           Schema(type=Type.STRING),
            "priority":     Schema(type=Type.INTEGER),
            "type": Schema(type=Type.STRING, enum=[
    "process_termination",   # maps to → process_termination()
    "file_quarantine",       # maps to → file_quarantine()
    "file_deletion",         # maps to → file_deletion()
    "ip_block",              # maps to → ip_block()
    "dns_block",             # maps to → dns_block()
    "host_isolation",        # maps to → host_isolation()
    "identity_revocation",   # maps to → identity_revocation()
    "patching",              # maps to → patching()
    "shutdown",              # maps to → shutdown()
    "alert",                 # maps to → alert()
   
]),
            "target_type":  Schema(type=Type.STRING, enum=[
                                "guid",  
                                "ip", "domain", "registry","file","user","host"
                            ]),
            "target_value": Schema(type=Type.STRING),
          
            "reason":       Schema(type=Type.STRING),
        },
        required=["id", "priority", "type", "target_type", "target_value", "reason"],
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
        subgraph: SubgraphContext,
    ) -> ResponderOutput:

        verdict = raw.get("verdict", "SUSPICIOUS")
        if verdict not in ("MALICIOUS", "SUSPICIOUS", "BENIGN-CONTEXT"):
            verdict = "SUSPICIOUS"
        result = ResponderOutput(
            anchor_guid      = subgraph.anchor_guid,
            verdict          = verdict,
            actions          = raw.get("actions", []),
            raw_llm_response = json.dumps(raw),
        )
        print(f"[AnalystAgent] verdict={verdict}  actions={len(result.actions)}")
        return result
    

    def analyse(
        self,
        subgraph: SubgraphContext,
    ) -> ResponderOutput:
        try:
            prompt = self._build_prompt(subgraph)
            raw    = self._call_llm(prompt)
            return self._parse(raw, subgraph)
        except Exception as exc:
            print(f"[AnalystAgent][ERROR] anchor={subgraph.anchor_guid[:20]}: {exc}")
            return self._error_output(subgraph, str(exc))

    # ── PROMPT ────────────────────────────────────────────────────────────────

    def _build_prompt(self, subgraph: SubgraphContext) -> str:
        sections = [
            self._s_header(subgraph),
            self._s_lookup_table(subgraph),
            self._s_process_tree(subgraph),
            self._s_behaviours(subgraph),
            #self._s_gaps(subgraph),
            #self._s_previous(case),
            self._s_task(),
        ]
        return "\n\n".join(s for s in sections if s)

    # ── SECTION 1: HEADER ─────────────────────────────────────────────────────

    def _s_header(self,  sg: SubgraphContext) -> str:
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

            # collect users across all instances of this template
            users = {
                inst.user
                for g in guids
                if (inst := next((i for i in sg.instances if i.guid == g), None))
                and inst.user
            }

            parts = [f"  tmpl={t_short}", f"image={tmpl.image or '?'}"]
            if tmpl.parent_image: parts.append(f"spawned-by={tmpl.parent_image}")
            if tmpl.cmdline:      parts.append(f"cmdline={tmpl.cmdline}")
            if len(users) == 1:   parts.append(f"user={next(iter(users))}")  # same for all → template level
            lines.append("  |  ".join(parts))

            for g in guids:
                inst      = next((i for i in sg.instances if i.guid == g), None)
                alive_tag = "alive" if (inst and inst.alive) else "dead"
                
                score_val = inst.score if inst else "?"
                # only show user per-instance when instances differ
                user_str  = f"  user={inst.user}" if (inst and inst.user and len(users) > 1) else ""
                lines.append(f"      guid={g}  score={score_val}    [{alive_tag}]{user_str}")

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
            if hasattr(inst, "pending_action") and inst.pending_action and not inst.pending_action=="alert":
                tags.append(f" ACTION={inst.pending_action}")
            tag_str = f"  [{','.join(tags)}]" if tags else ""
            
            t       = sg.templates.get(inst.template_hash or "")
            t_short = (inst.template_hash or "")[:12] or "no-tmpl"

            if inst.ghost or not t:
                lines.append(
                    f"{prefix}"
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
                attr=""
                if art.label in ("Driver", "Image"):
                    # id IS the sha256
                    path_str = f"  path={art.path}" if art.path else ""
                    #return f"{art.label}:sha256={art.id}{path_str}"
                    attr=path_str
                else:
                    attr=art.id
             
                if art.pending_action:
                    return f"{art.label}:{attr}  Action:[{art.pending_action}]"
                else:
                    return f"{art.label}:{attr}"
            return f"[MISSING:{node_id}]"

        sorted_edges = sorted(
            [e for e in sg.edges if e.first_seen],
            key=lambda e: e.first_seen,
        )

        lines = ["BEHAVIOURS (chronological):"]
        for e in sorted_edges:
            parts = [f"  {e.first_seen} -> {e.last_seen.split()[1] if e.last_seen else '?'} {e.rel_type}  score={e.total_score}"]
            src=_resolve(e.src_id)
            if "GHOST" in src:
                inst = inst_map.get(e.dst_id)
                t = (sg.templates.get(inst.template_hash)).parent_image
                src=f"{t}  (guid={src})"
                
            parts.append(f"    {src} → {_resolve(e.dst_id)}")
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

    '''def _s_previous(self, case: InvestigationCase) -> str:
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
        return "\n".join(lines)'''

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
  - ACTION TAGS: If a process shows ACTION=<type>, it means a containment action has already been decided and stamped on that node by the system (not yet necessarily executed). Use this as context to avoid redundant or conflicting actions and to reason about escalation or follow-up steps.
  - [MISSING:guid] = could not be fetched — note as gap.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ACTION TYPES — what each action does and when to use it:

  process_termination
      Kill a live process immediately by guid.
 file_quarantine
      Move a file to isolated quarantine.target_value MUST be the exact path from a CREATED_FILE or DELETED edge.
 file_deletion
      Permanently wipe a file (multi-pass). Use only when quarantine is not possible
      or the file is actively re-executing from quarantine. Never use as first choice.
 ip_block
      Block an IP at Windows Firewall (inbound + outbound).
      Use when a process connected to an external C2 or exfiltration endpoint.
      Always pair with a blacklist action on the same IP.
dns_block
      Block a domain via hosts file redirect + DNS cache flush.
      Prefer over ip_block when domain may resolve to multiple IPs (CDN, DGA, fast-flux).
      Always pair with a blacklist action on the same domain.
host_isolation
      Cut ALL network traffic on this host. DRASTIC and hard to reverse.
      Use ONLY when active exfiltration or ransomware spreading is confirmed.
identity_revocation
      Disable a Windows user account.
    
shutdown
      Shut down the host. Use only when isolation is insufficient and the threat is
      actively destroying data or spreading laterally beyond containment.

alert
      Raise a structured alert for human review. No automated containment.
      Use when: confidence is low, evidence is ambiguous, or a protected process
      shows elevated score .


      
REASON:
 explain every choice you made 


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
        import os
        
        # Save prompt
        try:
            os.makedirs("prompts", exist_ok=True)
            filename = f"prompts/prompt_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.log"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(prompt)
            print(f"[Analyst] prompt saved → {filename}  ({len(prompt)} chars)")
        except Exception as exc:
            print(f"[Analyst][ERROR] Failed to save prompt: {exc}")

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

            # Save response
            try:
                response_file = f"prompts/response_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
                with open(response_file, "w", encoding="utf-8") as f:
                    json.dump(result, f, indent=2)
                print(f"[Analyst] response saved → {response_file}")
            except Exception as exc:
                print(f"[Analyst][ERROR] Failed to save response: {exc}")

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
    def _error_output(subgraph: SubgraphContext, reason: str) -> ResponderOutput:
        return ResponderOutput(
            anchor_guid      = subgraph.anchor_guid,
            verdict          = "SUSPICIOUS",
            actions          = [],
            raw_llm_response = reason,
        )