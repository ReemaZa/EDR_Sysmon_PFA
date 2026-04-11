"""
Agent orchestrator: Coordinates event watcher and processes events through detection pipeline.

Responsibility: Manage the lifecycle, route events to pipeline, and handle alerts.

Flow: event_watcher → ingestion → pipeline → response/storage
"""
import os
import signal
import sys
import threading
import time

from src.core.event_watcher import SysmonEventWatcher
from src.core.pipeline import DetectionPipeline, ThreatLevel


# Global pipeline instance
detection_pipeline = None


def process_event(evt):
    """
    Main event processing entry point.
    
    Routes events through the detection pipeline:
    1. event_watcher delivers raw parsed events
    2. Pipeline runs all detection layers
    3. High-risk events trigger response actions
    4. All events logged to storage
    
    Args:
        evt: Normalized event dict from ingestion.parse_sysmon_event()
    """
    global detection_pipeline
    
    if detection_pipeline is None:
        return
    
    # Run event through detection pipeline
    verdict = detection_pipeline.process_event(evt)
    
    # Print brief event info
    event_type = evt.get('event_type', 'Unknown')
    event_id = evt.get('event_id', '?')
    timestamp = evt.get('timestamp', '')
    
    # Format based on threat level
    if verdict.is_malicious():
        alert_icon = "🔴 ALERT"
        threat_name = verdict.threat_level.name
    else:
        alert_icon = "ℹ️ "
        threat_name = "Clean"
    
    print(f"{alert_icon} [{event_id:2d}] {timestamp} | {event_type:30s} | Threat: {threat_name}")
    
    # Log detection details if threats found
    if verdict.layer_results:
        for result in verdict.layer_results:
            matches = ', '.join(result.matches[:2])  # Show first 2 matches
            print(f"       └─ {result.layer_name}: {result.threat_level.name} - {matches}")
    
    # TODO: Handle response actions for CRITICAL/HIGH threats
    # if verdict.is_malicious():
    #     trigger_response(evt, verdict)
    #
    # TODO: Log to storage
    # event_logger.log(evt, verdict)


def main():
    global detection_pipeline

    print("=" * 70)
    print("EDR SYSTEM - Sysmon Event Monitor")
    print("=" * 70)
    print("Starting event watcher...")
    print("Detection layers: L1 (Hash), L2 (Sigma), L3 (YARA), L4 (AI)")
    print("Press Ctrl+C to stop.\n")

    stop_event = threading.Event()

    detection_pipeline = DetectionPipeline(
        enable_l1=True,
        enable_l2=True,
        enable_l3=False,
        enable_l4=False,
    )

    watcher = SysmonEventWatcher(callback=process_event, stop_event=stop_event)

    # Define AFTER watcher and stop_event exist
    def _stop(signum, frame):
        print("\n" + "=" * 70)
        print("Stopping watcher...")
        stop_event.set()       # unblocks watcher's _stop_event.wait()
        watcher.stop()         # redundant but explicit
        watcher.join(timeout=5)
        if detection_pipeline:
            detection_pipeline.print_stats()
        print("=" * 70)
        sys.exit(0)            # ← important: actually exits

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    watcher.start()

    # Loop instead of a long blocking wait — allows signals to be processed
     #stop_event.wait()
    while not stop_event.is_set():
        time.sleep(0.2)
    if detection_pipeline:
        detection_pipeline.print_stats()
        
   

if __name__ == "__main__":
    main()
