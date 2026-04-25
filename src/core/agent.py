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
import logging
from datetime import datetime

from src.core.event_watcher import SysmonEventWatcher
from src.core.pipeline import DetectionPipeline, ThreatLevel
from src.graph.Graph_Builder import GraphBuilder

# ============================================================================
# LOGGING SETUP: Log all console output to both console and file
# ============================================================================
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, f"edr_agent_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

# Create a custom logger that also captures print() statements
class PrintLogger:
    """Captures print() output and sends it to both console and file"""
    def __init__(self, log_file):
        self.log_file = log_file
        self.terminal = sys.stdout
        self.log = open(log_file, 'a', encoding='utf-8')
    
    def write(self, message):
        try:
            self.terminal.write(message)
        except UnicodeEncodeError:
            # If console can't handle unicode, try replacing problematic chars
            safe_message = message.encode('utf-8', errors='replace').decode('utf-8', errors='replace')
            self.terminal.write(safe_message)
        
        # Always write to file as-is (file handles UTF-8)
        self.log.write(message)
        self.log.flush()
    
    def flush(self):
        self.terminal.flush()
        self.log.flush()
    
    def close(self):
        self.log.close()

# Redirect stdout to our custom logger
sys.stdout = PrintLogger(LOG_FILE)

# Toggle: when True, the agent will read events from a local test file using
# the LogReplayEngine (useful for testing). When False, it reads from live
# Sysmon via the event watcher.
# Set this to True or False as needed.
READ_FROM_FILE = True
# Path to the test log file (used only when READ_FROM_FILE == True)
LOG_REPLAY_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'tests', 'logs_dataset', 'windows-sysmon-T1003.001.txt')


# Global pipeline instance
detection_pipeline = None

# Self-identification state (mirrors hookSelfGUID logic)
_self_pid = os.getpid()
_self_guid = None          # Sysmon GUID of this EDR process, discovered at runtime
_self_guid_lock = threading.Lock()
EDR_IMAGE_MARKER = "EDR_Sysmon_PFA"  # Substring that identifies our image path

graph_builder=GraphBuilder()

def _is_edr_image(image_path: str) -> bool:
    """
    Return True if the image belongs to this EDR's directory tree.

    The executable may be python.exe, python3.exe, etc. — the reliable
    identifier is that the path lives under the EDR project directory,
    which always contains EDR_Sysmon_PFA as a path component.
    """
    if not image_path:
        return False
    # Normalize separators so both / and \ work
    normalized = image_path.replace("\\", "/")
    return EDR_IMAGE_MARKER in normalized


def _get_field(evt: dict, *keys: str):
    """
    Look up a field checking both the top-level dict and evt['data'].
    Accepts multiple key variants (e.g. 'image', 'Image').
    Returns the first non-None value found, or None.
    """
    data = evt.get("data", {}) or {}
    for key in keys:
        val = evt.get(key)
        if val is not None:
            return val
        val = data.get(key)
        if val is not None:
            return val
    return None


def _try_discover_self_guid(evt: dict) -> None:
    global _self_guid

    if _self_guid is not None:
        return

    with _self_guid_lock:
        if _self_guid is not None:
            return

        # --- Path 1: parent fields ---
        parent_image = _get_field(evt, "parent_image", "ParentImage")
        parent_pid   = _get_field(evt, "parent_pid",   "ParentProcessId")
        parent_guid  = _get_field(evt, "parent_guid",  "ParentProcessGuid")

        if _is_edr_image(str(parent_image or "")) and parent_guid:
            try:
                if int(parent_pid) == _self_pid:
                    _self_guid = parent_guid
                    print(f"[Self-ID] Found own GUID from parent fields: {_self_guid}")
                    return
            except (TypeError, ValueError):
                pass

        # --- Path 2: direct process fields ---
        image = _get_field(evt, "image", "Image")
        pid   = _get_field(evt, "pid",   "ProcessId")
        guid  = _get_field(evt, "guid",  "ProcessGuid")

        if _is_edr_image(str(image or "")) and guid:
            try:
                if int(pid) == _self_pid:
                    _self_guid = guid
                    print(f"[Self-ID] Found own GUID from process fields: {_self_guid}")
                    return
            except (TypeError, ValueError):
                pass


def _is_own_event(evt: dict) -> bool:
    # GUID-based check
    if _self_guid is not None:
        event_guid  = _get_field(evt, "guid",        "ProcessGuid")
        parent_guid = _get_field(evt, "parent_guid", "ParentProcessGuid")
        if event_guid == _self_guid or parent_guid == _self_guid:
            return True

    # Image+PID fallback
    image = _get_field(evt, "image", "Image")
    pid   = _get_field(evt, "pid",   "ProcessId")
    if _is_edr_image(str(image or "")):
        try:
            if int(pid) == _self_pid:
                return True
        except (TypeError, ValueError):
            pass

    return False

def process_event(evt):
    """
    Main event processing entry point.

    Routes events through the detection pipeline:
    1. event_watcher delivers raw parsed events
    2. Try to discover our own Sysmon GUID (no-op once found)
    3. Drop events that originate from this EDR process
    4. Pipeline runs all detection layers
    5. High-risk events trigger response actions
    6. All events logged to storage

    Args:
        evt: Normalized event dict from ingestion.parse_sysmon_event()
    """
    global detection_pipeline

    if detection_pipeline is None:
        return

    # Always attempt GUID discovery (cheap once _self_guid is set)
    _try_discover_self_guid(evt)

    # Drop events generated by this EDR — avoids noise and false positives
    if _is_own_event(evt):
        return


    # Print brief event info
    event_type = evt.get('event_type', 'Unknown')
    event_id   = evt.get('event_id', 0)
    timestamp  = evt.get('timestamp', '')
    
    # Get nested fields from data dict or top level
    data = evt.get('data', {})
    image = data.get('Image', evt.get('image', 'N/A'))
    guid = data.get('ProcessGuid', evt.get('guid', 'N/A'))
    user = data.get('User', evt.get('user', 'N/A'))
    parent_image = data.get('ParentImage', 'N/A')
    command_line = data.get('CommandLine', 'N/A')

    # Print enhanced event header
    print("\n" + "*" * 130)
    print(f"EVENT PROCESSING START: #{event_id}")
    print("=" * 130)
    print(f"  Event Type:     {event_type}")
    print(f"  Timestamp:      {timestamp}")
    print(f"  Image:          {image}")
    print(f"  Parent Image:   {parent_image}")
    print(f"  Command Line:   {command_line}")
    print(f"  GUID:           {guid}")
    print(f"  User:           {user}")
    print("=" * 130)

    # Run event through detection pipeline
    print(f"\n[PROCESSING] Running through detection layers...\n")
    verdict = detection_pipeline.process_event(evt)
    output = []
    
    # ================= GRAPH BUILDER =================
    print(f"\n[GRAPH] Building threat relationships in graph...\n")
    try:
        graph_detection = None
        
        if verdict and verdict.layer_results:
            for result in verdict.layer_results:
                if result.layer_name == "L2-Sigma":
                    graph_detection = result.metadata.get("graph_detection")
                    break
          
        graph_builder.process_event(evt, graph_detection)
    
    except Exception as e:
        print(f"  [ERROR] [GRAPH ERROR] {str(e)}")

    # Display results from each layer
    print("\n" + "_" * 130)
    print("DETECTION RESULTS FROM ALL LAYERS:")
    print("_" * 130)
    
    if verdict and verdict.layer_results:
        print(f"  Total Layers with Detections: {len(verdict.layer_results)}\n")
        
        for layer_idx, result in enumerate(verdict.layer_results, 1):
            print(result)
            
            output.append({
                "event": evt,
                "layer_name": result.layer_name,
                "threat_level": result.threat_level.name,
                "matches": result.matches,
                "metadata": result.metadata
            })
    else:
        print("  [OK] No detections from any layer (L1, L2, L3, L4)\n")
    
    # Print final verdict
    if verdict:
        threat_symbol = {
            'CRITICAL': '[CRITICAL]',
            'HIGH': '[HIGH]',
            'MEDIUM': '[MEDIUM]',
            'LOW': '[LOW]',
            'UNKNOWN': '[UNKNOWN]'
        }.get(verdict.threat_level.name, '[?]')
        print(f"  [VERDICT] FINAL VERDICT: {threat_symbol} {verdict.threat_level.name}")
    
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
    print(f"Self-exclusion: PID={_self_pid}, image marker='{EDR_IMAGE_MARKER}'")
    print("Press Ctrl+C to stop.\n")

    stop_event = threading.Event()

    detection_pipeline = DetectionPipeline(
        enable_l1=True,
        enable_l2=True,
        enable_l3=False,
        enable_l4=False,
    )

    # If READ_FROM_FILE is True, replay events from log file and exit
    if READ_FROM_FILE:
        try:
            # Import locally to avoid adding tests dependency to runtime when not used
            from tests.log_replay import LogReplayEngine

            print(f"[INFO] Running in log-replay mode. Reading events from: {LOG_REPLAY_FILE}")
            print(f"[INFO] After replay completes, the program will exit.\n")
            
            # Create engine with callback to use the same process_event logic
            engine = LogReplayEngine(
                log_file=LOG_REPLAY_FILE,
                enable_l1=detection_pipeline.enable_l1,
                enable_l2=detection_pipeline.enable_l2,
                enable_l3=detection_pipeline.enable_l3,
                enable_l4=detection_pipeline.enable_l4,
                event_callback=process_event  # ← Pass the callback so all agent logic is applied
            )
            # Replay events synchronously
            engine.replay(verbose=True)
            # Print pipeline stats from the engine's pipeline
            if engine.pipeline:
                engine.pipeline.print_stats()
            
            print("[INFO] Log replay completed. Exiting.\n")
            sys.exit(0)
        except Exception as e:
            print(f"[ERROR] Failed to run log replay engine: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

    # If READ_FROM_FILE is False, listen for real-time events
    watcher = SysmonEventWatcher(callback=process_event, stop_event=stop_event)

    # Define signal handlers
    def _stop(signum, frame):
        print("\n" + "=" * 70)
        print("Stopping watcher...")
        stop_event.set()
        watcher.stop()
        watcher.join(timeout=5)
        if detection_pipeline:
            detection_pipeline.print_stats()
        print("=" * 70)
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    # Start listening for real-time events
    watcher.start()

    # Loop instead of a long blocking wait — allows signals to be processed
    while not stop_event.is_set():
        time.sleep(0.2)

    if detection_pipeline:
        detection_pipeline.print_stats()


if __name__ == "__main__":
    main()