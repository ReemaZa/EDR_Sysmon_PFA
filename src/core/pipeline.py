"""
Detection Pipeline: Routes events through detection layers.

DATA FLOW:
    Event → L1 (Hash) → L2 (Sigma) → L3 (YARA) → Final Verdict

L4 (ThreatAnalyst) is NOT in the per-event flow.
It runs independently on a background timer, scanning the accumulated
graph every N seconds. It is started here and shut down here, but it
never receives individual events.
"""
import os
import sys
import time
from typing import Dict, Any, Optional, List

from src.core.config import ACTION_MODE
from src.core.utils import FinalVerdict, ThreatLevel
from src.detection.l2_sigma_detection.l2_sigma_engine import SigmaEngine


class DetectionPipeline:
    """
    Orchestrates L1–L3 per-event detection and owns the L4 ThreatAnalyst
    lifecycle (start on init, stop on shutdown).
    """

    def __init__(
        self,
        enable_l1: bool = True,
        enable_l2: bool = True,
        enable_l3: bool = False,
        enable_l4: bool = True,
        enable_l2_hash: bool = True,
        
        
    ):
        self.enable_l1 = enable_l1
        self.enable_l2 = enable_l2
        self.enable_l3 = enable_l3
        self.enable_l4 = enable_l4
        self._l2_timing_records: list = []
        self.l1_engine = None
        self.l2_engine = None
        self.l3_engine = None
        self.l4_analyst = None   # ThreatAnalyst — not called per-event

        if enable_l1:
            from src.detection.l1_hash_check.l1_hash_reputation import HashReputationEngine
            self.l1_engine = HashReputationEngine()

        if enable_l2:
            self.l2_engine = SigmaEngine(use_hash=enable_l2_hash)  

        # L4: ThreatAnalyst starts its background thread immediately on construction.
        # No separate start() call is needed or exists.
        if enable_l4:
            from src.detection.l4_llm_detection.threat_analyst import ThreatAnalyst
            self.l4_analyst = ThreatAnalyst(
                query_interval   =30,   # scan graph every 30 seconds
                threat_threshold = 4,    # investigate nodes with score >= 5
                max_subgraph_nodes = 120,
                action_executor_mode = ACTION_MODE,   # shared with remediation
            )

        self.stats = {
            "total_events": 0,
            "alerts":       0,
            "critical":     0,
            "layer_hits":   {"l1": 0, "l2": 0, "l3": 0},
                    "l2_checks":         0,
        "l2_total_time_ms":  0.0,
        "l2_min_time_ms":    float("inf"),
        "l2_max_time_ms":    0.0,

        }

    # ── PER-EVENT PROCESSING ─────────────────────────────────────────────────

    def process_event(self, event: Dict[str, Any]) -> FinalVerdict:
        """
        Run event through L1 → L2 → L3.
        L4 is intentionally absent here — it works on the accumulated graph,
        not on individual events.
        """
        event_id = str(event.get("event_id", "unknown"))
        verdict  = FinalVerdict(event_id, ThreatLevel.UNKNOWN)
        self.stats["total_events"] += 1

        # ── L1: Hash Reputation ───────────────────────────────────────────
        event_hashes = event.get("hashes", {})
        target_hash  = (
            event_hashes.get("sha256")
            or event_hashes.get("md5")
            or event_hashes.get("sha1")
        )

# → updates all 4 counters + prints per-event timing line
        if self.enable_l1 and self.l1_engine and target_hash:
            print("[DEBUG] Running L1 Hash check")
            l1_result = self.l1_engine.check_event(event)
            if l1_result:
                verdict.add_result(l1_result)
                self.stats["layer_hits"]["l1"] += 1
                if l1_result.threat_level == ThreatLevel.CRITICAL:
                    verdict.threat_level = ThreatLevel.CRITICAL
                    self.stats["critical"] += 1
                    self.stats["alerts"]   += 1
                    return verdict

        # ── L2: Sigma Rules ───────────────────────────────────────────────
        if self.enable_l2 and self.l2_engine:
            print("[DEBUG] Running L2 Sigma check")
            _l2_t0 = time.perf_counter()
            l2_result = self.l2_engine.check_event(event)
            _l2_elapsed_ms = (time.perf_counter() - _l2_t0) * 1000
            self.stats["l2_total_time_ms"] += _l2_elapsed_ms   # ← missing
            self.stats["l2_checks"]        += 1                 # ← missing
            self.stats["l2_min_time_ms"]    = min(self.stats["l2_min_time_ms"], _l2_elapsed_ms)  # ← missing
            self.stats["l2_max_time_ms"]    = max(self.stats["l2_max_time_ms"], _l2_elapsed_ms)  # ← missing
            self._l2_timing_records.append({
    "event_id":   event_id,
    "elapsed_ms": round(_l2_elapsed_ms, 4),
    "matched":    l2_result is not None,
    "cache_hit":  l2_result.metadata.get("cache_hit", False) if l2_result else False,
})
            if l2_result:
                verdict.add_result(l2_result)
                self.stats["layer_hits"]["l2"] += 1
                if l2_result.threat_level == ThreatLevel.CRITICAL:
                    verdict.threat_level = ThreatLevel.CRITICAL
                    self.stats["critical"] += 1
                    self.stats["alerts"]   += 1
                    return verdict

        # ── L3: YARA Scanner ──────────────────────────────────────────────
        if self.enable_l3 and self.l3_engine:
            print("[DEBUG] Running L3 YARA check")
            l3_result = self.l3_engine.check_event(event)
            if l3_result:
                verdict.add_result(l3_result)
                self.stats["layer_hits"]["l3"] += 1
                if l3_result.threat_level == ThreatLevel.CRITICAL:
                    verdict.threat_level = ThreatLevel.CRITICAL
                    self.stats["critical"] += 1
                    self.stats["alerts"]   += 1
                    return verdict

        # ── Aggregate ─────────────────────────────────────────────────────
        verdict.threat_level = self._aggregate(verdict)
        if verdict.is_malicious():
            self.stats["alerts"] += 1
        return verdict

    # ── AGGREGATION ───────────────────────────────────────────────────────────

    def _aggregate(self, verdict: FinalVerdict) -> ThreatLevel:
        if not verdict.layer_results:
            return ThreatLevel.UNKNOWN

        counts = {level: 0 for level in ThreatLevel}
        for r in verdict.layer_results:
            counts[r.threat_level] += 1

        if counts[ThreatLevel.CRITICAL] > 0:
            return ThreatLevel.CRITICAL
        if counts[ThreatLevel.HIGH] >= 2:
            return ThreatLevel.HIGH
        if counts[ThreatLevel.HIGH] == 1 and counts[ThreatLevel.MEDIUM] > 0:
            return ThreatLevel.HIGH
        if counts[ThreatLevel.MEDIUM] >= 2:
            return ThreatLevel.MEDIUM
        if counts[ThreatLevel.MEDIUM] >= 1:
            return ThreatLevel.LOW
        return ThreatLevel.UNKNOWN

    # ── STATS ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        stats = {**self.stats}

        if self.l1_engine:
            stats["l1_stats"] = self.l1_engine.get_stats()
 #       if self.l2_engine:
#            stats["l2_stats"] = self.l2_engine.get_stats()
        if self.l4_analyst:
            stats["l4_stats"] = self.l4_analyst.get_stats()

        total      = max(self.stats["total_events"], 1)
        alert_rate = (self.stats["alerts"] / total) * 100
        stats["alert_rate"] = f"{alert_rate:.2f}%"
        return stats

    def print_stats(self):
        stats = self.get_stats()
        print("\n" + "=" * 80)
        print("DETECTION PIPELINE STATISTICS")
        print("=" * 80)
        print(f"Total Events Processed: {stats['total_events']}")
        print(f"Events with Detections: {stats['alerts']} ({stats['alert_rate']})")
        print(f"Critical Alerts:        {stats['critical']}")
        print(f"\nLayer Detection Count:")
        print(f"  L1 (Hash):  {stats['layer_hits']['l1']}")
        print(f"  L2 (Sigma): {stats['layer_hits']['l2']}")
        print(f"  L3 (YARA):  {stats['layer_hits']['l3']}")

        if "l1_stats" in stats:
            l1 = stats["l1_stats"]
            print(f"\n[L1 Hash Details]")
            print(f"  Total Checks:   {l1.get('total_checks', 0)}")
            print(f"  Malware Hits:   {l1.get('malware_table_hits', 0)}")
            print(f"  API Queries:    {l1.get('api_queries', 0)}")
            print(f"  API Malicious:  {l1.get('api_malicious', 0)}")
            print(f"  Detection Rate: {l1.get('detection_rate', '0.00%')}")

        if "l2_stats" in stats:
            l2 = stats["l2_stats"]
            print(f"\n[L2 Sigma Details]")
            print(f"  Events Checked: {l2.get('total_checks', 0)}")
            print(f"  Rules Matched:  {l2.get('rule_matches', 0)}")

        if "l4_stats" in stats:
            l4 = stats["l4_stats"]
            print(f"\n[L4 Analyst Details]")
            print(f"  Ticks:              {l4.get('ticks', 0)}")
            print(f"  Components Analysed: {l4.get('components_analysed', 0)}")
            print(f"  Findings:           {l4.get('findings', 0)}")

        print("=" * 80 + "\n")
    def save_timing(self, output_dir: str = "timing_results", label: str = "") -> str:
        import json
        from datetime import datetime

        os.makedirs(output_dir, exist_ok=True)
        tag  = f"_{label}" if label else ""
        path = os.path.join(output_dir, f"l2_timing{tag}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

        n = self.stats["l2_checks"]
        payload = {
            "label": label,
            "summary": {
                "total_events_processed": self.stats["total_events"],
                "l2_events_timed":        n,
                "l2_total_time_ms":       round(self.stats["l2_total_time_ms"], 4),
                "l2_avg_time_ms":         round(self.stats["l2_total_time_ms"] / n, 4) if n else 0.0,
                "l2_min_time_ms":         round(self.stats["l2_min_time_ms"], 4) if n else 0.0,
                "l2_max_time_ms":         round(self.stats["l2_max_time_ms"], 4),
            },
            "records": self._l2_timing_records,
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        print(f"[TIMING] L2 timing saved → {path}")
        return path
    # ── SHUTDOWN ──────────────────────────────────────────────────────────────
    
    def shutdown(self):
        """Gracefully stop all background engines."""
        print("\n[PIPELINE] Shutting down...")
        if self.l4_analyst and self.enable_l4:
            self.l4_analyst.shutdown()
        print("[PIPELINE] Done.")