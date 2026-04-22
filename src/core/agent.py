"""
Agent orchestrator: Coordinates event watcher and processes events through detection pipeline.

Responsibility: Manage the lifecycle, route events to pipeline, and handle alerts.

Flow: event_watcher → ingestion → pipeline → response/storage
"""
import json
import os
import signal
import sys
import threading
import time

from src.core.event_watcher import SysmonEventWatcher
from src.core.pipeline import DetectionPipeline, ThreatLevel

# Toggle: when True, the agent will read events from a local test file using
# the LogReplayEngine (useful for testing). When False, it reads from live
# Sysmon via the event watcher.
# Set this to True or False as needed.
READ_FROM_FILE = True
# Path to the test log file (used only when READ_FROM_FILE == True)
LOG_REPLAY_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'tests', 'logs', 'windows-sysmon-T1003.001.txt')


# Global pipeline instance
detection_pipeline = None


def process_event(evt):
    """
    Main event processing entry point.
    
    Routes events through the detection pipeline:
    1. event_watcher delivers raw parsed events
    2. Pipeline runs all detection layers (L1, L2, L3)
    3. Collect and display all layer results
    4. Log results to storage
    
    Args:
        evt: Normalized event dict from ingestion.parse_sysmon_event()
    """
    global detection_pipeline
    
    if detection_pipeline is None:
        return
    
    # Run event through detection pipeline
    verdict = detection_pipeline.process_event(evt)
    
    # Extract event information
    event_type = evt.get('event_type', 'Unknown')
    event_id = evt.get('event_id', '?')
    timestamp = evt.get('timestamp', '')
    computer = evt.get('computer', 'Unknown')
    image = evt.get('image', 'N/A')
    
    # Print clear event header
    print("\n" + "=" * 10)
    print(f"📋 EVENT #{event_id:4d} | Type: {event_type:20s} | Time: {timestamp}")
    print(f"   Computer: {computer:30s} | Process: {image}")
    print("=" * 10)
    
    output = []
    
    # Display results from each layer
    if verdict.layer_results:
        for result in verdict.layer_results:
            layer_name = result.layer_name
            threat_level = result.threat_level.name
            
            # Layer header with threat level
            if threat_level == "CRITICAL":
                layer_icon = "🔴"
            elif threat_level == "HIGH":
                layer_icon = "🟠"
            elif threat_level == "MEDIUM":
                layer_icon = "🟡"
            else:
                layer_icon = "🟢"
            
            print(f"\n{layer_icon} {layer_name:20s} [{threat_level:10s}]")
            print("   " + "-" * 110)
            
            # Display all matches
            if result.matches:
                print(f"   Matches ({len(result.matches)}):")
                for idx, match in enumerate(result.matches, 1):
                    print(f"      [{idx}] {match}")
            else:
                print(f"   ✓ No matches detected")
            
            # Display metadata
            if result.metadata:
                print(f"\n   Details:")
                metadata = result.metadata
                
                # Handle different metadata structures based on layer
                if isinstance(metadata, dict):
                    for key, value in metadata.items():
                        if isinstance(value, (str, int, float, bool)):
                            print(f"      • {key}: {value}")
                        elif isinstance(value, list):
                            print(f"      • {key}: {', '.join(map(str, value[:3]))}{'...' if len(value) > 3 else ''}")
                        elif isinstance(value, dict):
                            print(f"      • {key}: {str(value)[:80]}...")
                else:
                    print(f"      {str(metadata)[:100]}")
            
            print("   " + "-" * 110)
            
            output.append({
                "event": evt,
                "layer_name": layer_name,
                "threat_level": threat_level,
                "matches": result.matches,
                "metadata": result.metadata
            })
    else:
        print(f"\n✅ No detections from any layer (L1, L2, L3)")
        print("   " + "-" * 110)
    
    print("=" * 120)
    
    # Save to file AFTER the loop
    with open("results.json", "a") as f:
        json.dump(output, f, indent=4)
    
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

    # If READ_FROM_FILE is True, use the LogReplayEngine instead of the live watcher
    if READ_FROM_FILE:
        try:
            # Import locally to avoid adding tests dependency to runtime when not used
            from tests.log_replay import LogReplayEngine

            print(f"[INFO] Running in log-replay mode. Reading events from: {LOG_REPLAY_FILE}")
            # Use the same layers configuration as the detection_pipeline above
            engine = LogReplayEngine(
                log_file=LOG_REPLAY_FILE,
                enable_l1=detection_pipeline.enable_l1,
                enable_l2=detection_pipeline.enable_l2,
                enable_l3=detection_pipeline.enable_l3,
                enable_l4=detection_pipeline.enable_l4,
            )
            # Replay events synchronously and print a summary
            engine.replay(verbose=True)
            # Print pipeline stats from the engine's pipeline
            if engine.pipeline:
                engine.pipeline.print_stats()
            sys.exit(0)
        except Exception as e:
            print(f"[ERROR] Failed to run log replay engine: {e}")

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
