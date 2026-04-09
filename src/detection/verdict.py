"""
Verdict and Scoring Logic

Responsibility: Additional scoring utilities and verdict helpers.

The main verdict logic is in pipeline.py, but this module provides:
- Score calculation utilities
- Verdict interpretation helpers
- Response action recommendation
"""
from typing import List, Dict, Any
from src.core.pipeline import FinalVerdict, ThreatLevel, DetectionResult


def calculate_risk_score(verdict: FinalVerdict) -> float:
    """
    Calculate a numeric risk score (0-100) from a verdict.
    
    Scoring weights:
    - CRITICAL: 100
    - HIGH: 75
    - MEDIUM: 50
    - LOW: 25
    - UNKNOWN: 0
    
    Multiple layers add confidence bonus.
    
    Args:
        verdict: FinalVerdict object
    
    Returns:
        Risk score between 0 and 100
    """
    if not verdict.layer_results:
        return 0.0
    
    # Base scores by threat level
    level_scores = {
        ThreatLevel.CRITICAL: 100,
        ThreatLevel.HIGH: 75,
        ThreatLevel.MEDIUM: 50,
        ThreatLevel.LOW: 25,
        ThreatLevel.UNKNOWN: 0
    }
    
    # Get max score from any layer
    max_score = max(
        (level_scores[result.threat_level] for result in verdict.layer_results),
        default=0
    )
    
    # Add confidence bonus for multiple layers agreeing
    num_layers = len(verdict.layer_results)
    if num_layers >= 3:
        max_score = min(100, max_score * 1.2)  # 20% bonus
    elif num_layers >= 2:
        max_score = min(100, max_score * 1.1)  # 10% bonus
    
    return round(max_score, 2)


def recommend_action(verdict: FinalVerdict) -> str:
    """
    Recommend response action based on verdict.
    
    Args:
        verdict: FinalVerdict object
    
    Returns:
        Recommended action: "block", "quarantine", "alert", "log"
    """
    if verdict.threat_level == ThreatLevel.CRITICAL:
        return "block"  # Kill process immediately
    elif verdict.threat_level == ThreatLevel.HIGH:
        return "quarantine"  # Isolate file/process
    elif verdict.threat_level == ThreatLevel.MEDIUM:
        return "alert"  # Alert SOC team
    else:
        return "log"  # Just log for review


def get_verdict_summary(verdict: FinalVerdict) -> Dict[str, Any]:
    """
    Get a comprehensive summary of a verdict.
    
    Args:
        verdict: FinalVerdict object
    
    Returns:
        Dictionary with verdict details
    """
    return {
        'event_id': verdict.event_id,
        'threat_level': verdict.threat_level.name,
        'risk_score': calculate_risk_score(verdict),
        'is_malicious': verdict.is_malicious(),
        'recommended_action': recommend_action(verdict),
        'layers_triggered': len(verdict.layer_results),
        'detection_details': [
            {
                'layer': result.layer_name,
                'threat': result.threat_level.name,
                'matches': result.matches,
                'metadata': result.metadata
            }
            for result in verdict.layer_results
        ],
        'timestamp': verdict.timestamp
    }


def format_verdict_report(verdict: FinalVerdict) -> str:
    """
    Format verdict as a human-readable report.
    
    Args:
        verdict: FinalVerdict object
    
    Returns:
        Multi-line string report
    """
    summary = get_verdict_summary(verdict)
    
    lines = [
        "=" * 60,
        f"THREAT DETECTION REPORT - Event {verdict.event_id}",
        "=" * 60,
        f"Threat Level:       {summary['threat_level']}",
        f"Risk Score:         {summary['risk_score']}/100",
        f"Recommended Action: {summary['recommended_action'].upper()}",
        f"Layers Triggered:   {summary['layers_triggered']}",
        ""
    ]
    
    if verdict.layer_results:
        lines.append("Detection Details:")
        lines.append("-" * 60)
        for detail in summary['detection_details']:
            lines.append(f"  [{detail['layer']}] {detail['threat']}")
            for match in detail['matches']:
                lines.append(f"    - {match}")
            lines.append("")
    
    lines.append("=" * 60)
    
    return "\n".join(lines)
