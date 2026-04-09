"""
Detection Pipeline: Routes events through detection layers

RESPONSIBILITY:
    - Receive events from agent
    - Pass events to each detection layer (L1, L2, L3, L4)
    - Collect results from each layer
    - Create final verdict
    - Track statistics

DATA FLOW:
    Event → L1 → L2 → L3 → L4 → Final Verdict
    
CLASSES:
    - ThreatLevel: Enum for severity (UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL)
    - DetectionResult: What each layer returns when it finds a threat
    - FinalVerdict: Aggregated results from all layers
    - DetectionPipeline: Main orchestrator
"""
from typing import Dict, Any, Optional, List
from enum import Enum
import time


# ============================================================================
# THREAT LEVEL ENUM
# ============================================================================
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


# ============================================================================
# DETECTION PIPELINE CLASS
# ============================================================================
class DetectionPipeline:
    """
    Main detection pipeline - runs events through all layers.
    
    PROCESS:
    1. Event arrives
    2. Pass to L1 (Hash Reputation) → get result
    3. Pass to L2 (Sigma Rules) → get result
    4. Pass to L3 (YARA Scanner) → get result
    5. Pass to L4 (AI/ML Engine) → get result
    6. Aggregate all results → create final verdict
    7. Return verdict
    
    OPTIMIZATION:
    - If any layer returns CRITICAL, stop immediately (early exit)
    - This saves time on obvious threats
    
    USAGE:
        pipeline = DetectionPipeline(enable_l1=True, enable_l2=False)
        verdict = pipeline.process_event(event)
        
        if verdict.is_malicious():
            print("THREAT DETECTED!")
    """
    
    def __init__(self, enable_l1=True, enable_l2=True, enable_l3=True, enable_l4=False):
        """
        Initialize the pipeline.
        
        Args:
            enable_l1 (bool): Enable L1 Hash Reputation
            enable_l2 (bool): Enable L2 Sigma Rules
            enable_l3 (bool): Enable L3 YARA Scanner
            enable_l4 (bool): Enable L4 AI/ML Engine
        """
        self.enable_l1 = enable_l1
        self.enable_l2 = enable_l2
        self.enable_l3 = enable_l3
        self.enable_l4 = enable_l4
        
        # Initialize detection engines
        self.l1_engine = None
        self.l2_engine = None
        self.l3_engine = None
        self.l4_engine = None
        
        # Load L1 engine if enabled
        if enable_l1:
            from src.detection.l1_hash_reputation import HashReputationEngine
            self.l1_engine = HashReputationEngine()
        
        # L2-L4 will be loaded when implemented
        # if enable_l2:
        #     from src.detection.l2_sigma_engine import SigmaEngine
        #     self.l2_engine = SigmaEngine()
        
        # Statistics
        self.stats = {
            'total_events': 0,       # How many events processed
            'alerts': 0,             # How many threats found
            'critical': 0,           # How many CRITICAL threats
            'layer_hits': {          # Detections per layer
                'l1': 0,
                'l2': 0,
                'l3': 0,
                'l4': 0
            }
        }
    
    def process_event(self, event: Dict[str, Any]) -> FinalVerdict:
        """
        Process an event through all detection layers.
        
        FLOW:
        1. Create empty verdict
        2. Run L1 → add result if found
        3. Run L2 → add result if found
        4. Run L3 → add result if found
        5. Run L4 → add result if found
        6. Aggregate threat levels
        7. Return verdict
        
        INPUT (event):
            {
                'event_id': 1,
                'event_type': 'ProcessCreate',
                'event_record_id': 12345,
                'image': 'C:\\malware.exe',
                'hashes': 'SHA256=abc123...'
            }
        
        OUTPUT (FinalVerdict):
            FinalVerdict(
                event_id="12345",
                threat_level=ThreatLevel.CRITICAL,
                layer_results=[DetectionResult(...), DetectionResult(...)]
            )
        
        Args:
            event (Dict): Normalized Sysmon event
        
        Returns:
            FinalVerdict: Final detection verdict
        """
        # Get event ID for tracking
        event_id = str(event.get('event_record_id', 'unknown'))
        
        # Create empty verdict
        verdict = FinalVerdict(event_id, ThreatLevel.UNKNOWN)
        
        # Track this event
        self.stats['total_events'] += 1
        
        # ===== LAYER 1: Hash Reputation =====
        if self.enable_l1 and self.l1_engine:
            l1_result = self.l1_engine.check_event(event)
            if l1_result:
                verdict.add_result(l1_result)
                self.stats['layer_hits']['l1'] += 1
                
                # Early exit on CRITICAL
                if l1_result.threat_level == ThreatLevel.CRITICAL:
                    verdict.threat_level = ThreatLevel.CRITICAL
                    self.stats['critical'] += 1
                    self.stats['alerts'] += 1
                    return verdict
        
        # ===== LAYER 2: Sigma Rules =====
        if self.enable_l2 and self.l2_engine:
            l2_result = self.l2_engine.check_event(event)
            if l2_result:
                verdict.add_result(l2_result)
                self.stats['layer_hits']['l2'] += 1
                
                # Early exit on CRITICAL
                if l2_result.threat_level == ThreatLevel.CRITICAL:
                    verdict.threat_level = ThreatLevel.CRITICAL
                    self.stats['critical'] += 1
                    self.stats['alerts'] += 1
                    return verdict
        
        # ===== LAYER 3: YARA Scanner =====
        if self.enable_l3 and self.l3_engine:
            l3_result = self.l3_engine.check_event(event)
            if l3_result:
                verdict.add_result(l3_result)
                self.stats['layer_hits']['l3'] += 1
                
                # Early exit on CRITICAL
                if l3_result.threat_level == ThreatLevel.CRITICAL:
                    verdict.threat_level = ThreatLevel.CRITICAL
                    self.stats['critical'] += 1
                    self.stats['alerts'] += 1
                    return verdict
        
        # ===== LAYER 4: AI/ML Engine =====
        if self.enable_l4 and self.l4_engine:
            l4_result = self.l4_engine.check_event(event)
            if l4_result:
                verdict.add_result(l4_result)
                self.stats['layer_hits']['l4'] += 1
                
                # Early exit on CRITICAL
                if l4_result.threat_level == ThreatLevel.CRITICAL:
                    verdict.threat_level = ThreatLevel.CRITICAL
                    self.stats['critical'] += 1
                    self.stats['alerts'] += 1
                    return verdict
        
        # ===== AGGREGATE RESULTS =====
        verdict.threat_level = self._aggregate_threat_level(verdict)
        
        # Count alerts
        if verdict.is_malicious():
            self.stats['alerts'] += 1
        
        return verdict
    
    def _aggregate_threat_level(self, verdict: FinalVerdict) -> ThreatLevel:
        """
        Combine threat levels from all layers into final verdict.
        
        RULES:
        - CRITICAL: Any layer says CRITICAL
        - HIGH: 2+ layers say HIGH, OR 1 HIGH + 1 MEDIUM
        - MEDIUM: 2+ layers say MEDIUM
        - LOW: 1 layer says MEDIUM
        - UNKNOWN: No detections
        
        Args:
            verdict (FinalVerdict): Verdict with layer results
        
        Returns:
            ThreatLevel: Final aggregated threat level
        """
        if not verdict.layer_results:
            return ThreatLevel.UNKNOWN
        
        # Count how many layers reported each level
        level_counts = {level: 0 for level in ThreatLevel}
        for result in verdict.layer_results:
            level_counts[result.threat_level] += 1
        
        # Aggregate logic
        if level_counts[ThreatLevel.CRITICAL] > 0:
            return ThreatLevel.CRITICAL
        elif level_counts[ThreatLevel.HIGH] >= 2:
            return ThreatLevel.HIGH
        elif level_counts[ThreatLevel.HIGH] == 1 and level_counts[ThreatLevel.MEDIUM] > 0:
            return ThreatLevel.HIGH
        elif level_counts[ThreatLevel.MEDIUM] >= 2:
            return ThreatLevel.MEDIUM
        elif level_counts[ThreatLevel.MEDIUM] >= 1:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.UNKNOWN
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get pipeline statistics.
        
        OUTPUT FORMAT:
            {
                'total_events': 1000,
                'alerts': 25,
                'critical': 5,
                'alert_rate': '2.50%',
                'layer_hits': {'l1': 20, 'l2': 5, 'l3': 0, 'l4': 0},
                'l1_stats': {...}  # If L1 engine exists
            }
        """
        stats_dict = {**self.stats}
        
        # Add L1 engine stats if available
        if self.l1_engine:
            stats_dict['l1_stats'] = self.l1_engine.get_stats()
        
        # Calculate alert rate
        total = max(self.stats['total_events'], 1)
        alert_rate = (self.stats['alerts'] / total) * 100
        stats_dict['alert_rate'] = f"{alert_rate:.2f}%"
        
        return stats_dict
    
    def print_stats(self):
        """Print statistics to console in a readable format."""
        stats = self.get_stats()
        
        print("\n" + "="*60)
        print("DETECTION PIPELINE STATISTICS")
        print("="*60)
        print(f"Total Events Processed: {stats['total_events']}")
        print(f"Alerts Generated:       {stats['alerts']} ({stats['alert_rate']})")
        print(f"Critical Alerts:        {stats['critical']}")
        print(f"\nLayer Detections:")
        print(f"  L1 (Hash):  {stats['layer_hits']['l1']}")
        print(f"  L2 (Sigma): {stats['layer_hits']['l2']}")
        print(f"  L3 (YARA):  {stats['layer_hits']['l3']}")
        print(f"  L4 (AI):    {stats['layer_hits']['l4']}")
        
        # Print L1 detailed stats if available
        if 'l1_stats' in stats:
            l1 = stats['l1_stats']
            print(f"\nL1 Hash Reputation Details:")
            print(f"  Total Checks:     {l1['total_checks']}")
            print(f"  Blacklist Hits:   {l1['blacklist_hits']}")
            print(f"  Blacklist Size:   {l1['blacklist_size']}")
        
        print("="*60 + "\n")
