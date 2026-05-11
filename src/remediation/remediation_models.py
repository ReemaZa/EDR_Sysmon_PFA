"""
remediation_models.py  —  Shared dataclasses for the Remediation Module.

No logic, no imports from other remediation modules → zero circular deps.
Every other remediation module imports from here.

Hierarchy of objects produced by the pipeline:

  IncidentGroup
      └─ produced by IncidentGrouper
      └─ represents one logical incident (N GUIDs sharing a PAT ancestry)

  IncidentLineage
      └─ produced by LineageBuilder
      └─ wraps an IncidentGroup with full PAT ancestry + blast-radius data

  RemediationFinding
      └─ a single forensic observation made by the RemediationAgent
      └─ categorised: persistence | exfiltration | backdoor | other

  RemediationReport
      └─ the final output of one RemediationAgent run
      └─ saved to disk as remediation_reports/<incident_id>.json
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ══════════════════════════════════════════════════════════════════════════════
# INCIDENT GROUPING
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class IncidentGroup:
    """
    One logical incident: a cluster of GUIDs that share a common PAT ancestor.

    Fields
    ------
    incident_id   : auto-generated UUID, used as the report filename stem.
    root_guid     : the highest common ancestor GUID found in PAT.
                    LineageBuilder calls pat.build_remediation_context(root_guid)
                    so the blast-radius covers the entire group.
    member_guids  : every GUID in this cluster (includes root_guid).
    """
    root_guid:    str
    member_guids: List[str]
    incident_id:  str = field(default_factory=lambda: str(uuid.uuid4()))


# ══════════════════════════════════════════════════════════════════════════════
# LINEAGE (PAT enrichment of an IncidentGroup)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class IncidentLineage:
    """
    Full forensic context for one IncidentGroup, fetched from the PAT.

    Fields mirror pat.build_remediation_context() output plus the group itself.

    ancestry_chain   : list of process-node dicts, root → flagged node.
                       Each dict has: guid, image, cmdline, user, pid,
                       alive, start_time, end_time, integrity_level,
                       signature, signed, actions (full raw PAT stream).
    blast_radius     : flagged node + all descendants (downward BFS).
                       These are the kill / sweep candidates.
    injection_victims: processes outside the blast radius that received a
                       remote thread from a blast-radius process.
                       Need scanning, NOT killing.
    chain_truncated  : True if the upward walk hit a missing PAT key
                       (process predated monitoring or TTL expired).
    """
    group:             IncidentGroup
    ancestry_chain:    List[Dict[str, Any]]
    blast_radius:      List[Dict[str, Any]]
    injection_victims: List[Dict[str, Any]]
    chain_truncated:   bool


# ══════════════════════════════════════════════════════════════════════════════
# REMEDIATION FINDINGS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class RemediationFinding:
    """
    One discrete forensic observation produced by the RemediationAgent.

    category   : "persistence" | "exfiltration" | "backdoor" | "lateral_movement" | "other"
    severity   : "critical" | "high" | "medium" | "low"
    guid       : the process GUID this finding originated from.
    description: human-readable explanation of what was found.
    evidence   : raw data that supports the finding (file path, registry key,
                 IP address, domain, etc.) — whatever the LLM tool call returned.
    iocs       : list of extracted IOC strings (IPs, hashes, domains, paths).
    """
    category:    str          # persistence | exfiltration | backdoor | lateral_movement | other
    severity:    str          # critical | high | medium | low
    guid:        str
    description: str
    evidence:    Dict[str, Any] = field(default_factory=dict)
    iocs:        List[str]      = field(default_factory=list)


# ══════════════════════════════════════════════════════════════════════════════
# REMEDIATION REPORT  (final output of one RemediationAgent run)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class RemediationReport:
    """
    Complete forensic report for one incident, produced by RemediationAgent.

    Fields
    ------
    incident_id        : matches IncidentGroup.incident_id — used as filename.
    root_guid          : IncidentGroup.root_guid.
    produced_at        : ISO-8601 UTC timestamp.
    findings           : all RemediationFinding objects the agent produced.
    cleanup_actions    : ordered list of dicts the operator/automation should
                         execute to fully remediate the incident.
                         Each dict: {priority, action_type, target, reason}
    ioc_list           : deduplicated master IOC list across all findings.
    narrative          : freeform forensic summary written by the LLM.
    tool_call_log      : ordered log of every tool the agent called and the
                         result it received — full audit trail.
    raw_llm_response   : the last raw JSON string returned by Gemini.
    """
    incident_id:      str
    root_guid:        str
    produced_at:      str
    findings:         List[RemediationFinding]
    cleanup_actions:  List[Dict[str, Any]]
    ioc_list:         List[str]
    narrative:        str
    tool_call_log:    List[Dict[str, Any]] = field(default_factory=list)
    raw_llm_response: str = ""
