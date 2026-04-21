from src.core.utils import ThreatLevel


SEVERITY_MAP = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}
SCORE_TO_THREAT = {
    1: ThreatLevel.LOW,
    2: ThreatLevel.MEDIUM,
    3: ThreatLevel.HIGH,
    4: ThreatLevel.CRITICAL
}