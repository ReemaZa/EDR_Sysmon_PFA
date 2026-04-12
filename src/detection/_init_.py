"""
Detection module - Multi-layer threat detection engines.

LAYERS:
    L1: Hash Reputation (local blacklist) ✅ IMPLEMENTED
    L2: Sigma Rules (behavioral patterns)  ✅ IMPLEMENTED
    L3: YARA Scanner (malware signatures) 🚧 TODO
    L4: AI/ML Engine (anomaly detection) 🚧 TODO

INTERFACE:
    All engines must implement:
    - __init__(config_path): Initialize engine
    - check_event(event): Check event, return DetectionResult or None
    - get_stats(): Return statistics dict
"""

from src.detection.l1_hash_check.l1_hash_reputation import HashReputationEngine
# from src.detection.l2_sigma_engine import SigmaEngine
# from src.detection.l3_yara_scanner import YaraScanner
# from src.detection.l4_ai_engine import AIEngine

__all__ = [
    'HashReputationEngine',
    # 'SigmaEngine',
    # 'YaraScanner',
    # 'AIEngine',
]
