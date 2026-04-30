"""
l4_models.py  —  Shared dataclasses for the L4 analyst layer.

No logic, no imports from other L4 modules → no circular dependencies.
Every other L4 module imports from here.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ResponderOutput:
    anchor_guid:       str
    verdict:           str                  # "MALICIOUS" | "SUSPICIOUS"
    actions:           List[Dict[str, Any]] # executor reads this
    raw_llm_response:  str
    analysis_id:       str = field(default_factory=lambda: str(uuid.uuid4()))



# analysis_id and case_id are kept for logging/file output only
@dataclass
class AnalysisRecord:
    analysis_id:      str
    anchor_guid:      str
    verdict:          str
    actions:          List[Dict[str, Any]]
    raw_llm_response: str