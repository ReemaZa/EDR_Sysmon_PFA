
# ============================================================================
# THREAT LEVEL ENUM
# ============================================================================
from enum import Enum
import time
from typing import Any, Dict, List


class ThreatLevel(Enum):
    """
    Threat severity levels.
    
    Values are integers so we can compare: CRITICAL > HIGH > MEDIUM > LOW
    """
    UNKNOWN = 0   # No detection / not sure
    LOW = 1       # Suspicious but probably not dangerous
    MEDIUM = 2    # Potentially malicious
    HIGH = 3      # Likely malicious - should alert
    CRITICAL = 4  # Definitely malicious - BLOCK IMMEDIATELY


# ============================================================================
# DETECTION RESULT CLASS
# ============================================================================
class DetectionResult:
    """
    Result from a single detection layer.
    
    This is what L1, L2, L3, L4 return when they find a threat.
    
    FIELDS:
        layer_name (str): Which layer detected it ("L1-Hash", "L2-Sigma", etc.)
        threat_level (ThreatLevel): How dangerous (UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL)
        matches (List[str]): What was detected (e.g., ["Hash abc123 in blacklist"])
        metadata (Dict): Extra information (e.g., {'hash': 'abc123', 'file': 'malware.exe'})
        timestamp (float): When detected (auto-generated)
    
    EXAMPLE:
        result = DetectionResult(
            layer_name="L1-Hash",
            threat_level=ThreatLevel.CRITICAL,
            matches=["Hash abc123 found in blacklist"],
            metadata={'hash': 'abc123', 'file': 'C:\\malware.exe'}
        )
    """
    
    def __init__(self, layer_name: str, threat_level: ThreatLevel, 
                 matches: List[str], metadata: Dict[str, Any] = None):
        self.layer_name = layer_name          # str: "L1-Hash", "L2-Sigma", etc.
        self.threat_level = threat_level      # ThreatLevel enum
        self.matches = matches                # List[str]: What matched
        self.metadata = metadata or {}        # Dict: Extra info
        self.timestamp = time.time()          # float: Unix timestamp
    
    def __repr__(self):
        return f"DetectionResult(layer={self.layer_name}, level={self.threat_level.name}, matches={len(self.matches)})"
    
    def __str__(self):
        """Pretty string representation with metadata."""
        threat_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🔵',
            'UNKNOWN': '⚪'
        }.get(self.threat_level.name, '❓')
        
        result_str = f"\n  [{self.layer_name}] {threat_emoji} {self.threat_level.name}\n"
        result_str += f"    ├─ Matches: {len(self.matches)}\n"
        
        if self.matches:
            for idx, match in enumerate(self.matches, 1):
                result_str += f"    │  [{idx}] {match}\n"
        
        if self.metadata:
            result_str += f"    ├─ Metadata:\n"
            if 'source' in self.metadata:
                result_str += f"    │  ├─ Source: {self.metadata['source']}\n"
            if 'count' in self.metadata:
                result_str += f"    │  ├─ Count: {self.metadata['count']}\n"
            
            if 'rules' in self.metadata and self.metadata['rules']:
                rules = self.metadata['rules']
                result_str += f"    │  ├─ Rules ({len(rules)}):\n"
                for idx, rule in enumerate(rules[:3], 1):
                    result_str += f"    │  │  {idx}. {rule}\n"
                if len(rules) > 3:
                    result_str += f"    │  │  ... and {len(rules) - 3} more\n"
            
            if 'graph_detection' in self.metadata and self.metadata['graph_detection']:
                gd = self.metadata['graph_detection']
                result_str += f"    │  ├─ Graph Detection:\n"
                result_str += f"    │  │  ├─ Score: {gd.get('total_score', 0)}\n"
                result_str += f"    │  │  ├─ Findings: {len(gd.get('finding_ids', []))}\n"
                
                techniques = gd.get('techniques', [])
                tactics = gd.get('tactics', [])
                
                if techniques:
                    tech_str = ', '.join(techniques[:2])
                    if len(techniques) > 2:
                        tech_str += f" ... +{len(techniques)-2}"
                    result_str += f"    │  │  ├─ Techniques: {tech_str}\n"
                
                if tactics:
                    tac_str = ', '.join(tactics[:2])
                    if len(tactics) > 2:
                        tac_str += f" ... +{len(tactics)-2}"
                    result_str += f"    │  │  └─ Tactics: {tac_str}\n"
            
            result_str += f"    └─ End Metadata\n"
        
        return result_str


# ============================================================================
# FINAL VERDICT CLASS
# ============================================================================
class FinalVerdict:
    """
    Final verdict after all detection layers run.
    
    Combines results from all layers (L1, L2, L3, L4) into one verdict.
    
    FIELDS:
        event_id (str): Unique identifier for the event
        threat_level (ThreatLevel): Final aggregated threat level
        layer_results (List[DetectionResult]): Results from each layer that detected something
        timestamp (float): When verdict was created
        action_taken (str): What action was taken (e.g., "blocked", "logged")
    
    METHODS:
        add_result(result): Add a layer's detection result
        is_malicious(): Returns True if threat_level >= HIGH
        summary(): Returns human-readable summary string
    
    EXAMPLE:
        verdict = FinalVerdict(event_id="12345", threat_level=ThreatLevel.CRITICAL)
        verdict.add_result(l1_result)
        verdict.add_result(l2_result)
        
        if verdict.is_malicious():
            print(verdict.summary())
            # Output: "Event 12345: CRITICAL - 2 layer(s) alerted"
    """
    
    def __init__(self, event_id: str, threat_level: ThreatLevel):
        self.event_id = event_id                      # str: Event identifier
        self.threat_level = threat_level              # ThreatLevel: Final verdict
        self.layer_results: List[DetectionResult] = [] # List of layer results
        self.timestamp = time.time()                  # float: When created
        self.action_taken = None                      # str: Action taken (if any)
    
    def add_result(self, result: DetectionResult):
        """Add a detection result from a layer."""
        self.layer_results.append(result)
    
    def is_malicious(self) -> bool:
        """Check if this is a real threat (HIGH or CRITICAL)."""
        return self.threat_level.value >= ThreatLevel.HIGH.value
    
    def summary(self) -> str:
        """Get a one-line summary of the verdict."""
        return f"Event {self.event_id}: {self.threat_level.name} - {len(self.layer_results)} layer(s) alerted"