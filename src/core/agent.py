"""
Agent orchestrator: Coordinates event watcher and processes events through detection pipeline.

Responsibility: Manage the lifecycle, route events to pipeline, and handle alerts.

Flow: event_watcher / log_replay → process_event() → pipeline → response/storage

Both live (SysmonEventWatcher) and replay (LogReplayEngine) modes feed into the
same process_event() function. The only difference is the event source.
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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)


class PrintLogger:
    """Captures print() output and sends it to both console and file."""

    def __init__(self, log_file):
        self.log_file = log_file
        self.terminal = sys.stdout
        self.log = open(log_file, 'a', encoding='utf-8')

    def write(self, message):
        try:
            self.terminal.write(message)
        except UnicodeEncodeError:
            safe_message = message.encode('utf-8', errors='replace').decode('utf-8', errors='replace')
            self.terminal.write(safe_message)
        self.log.write(message)
        self.log.flush()

    def flush(self):
        self.terminal.flush()
        self.log.flush()

    def close(self):
        self.log.close()


sys.stdout = PrintLogger(LOG_FILE)

# ============================================================================
# CONFIGURATION
# ============================================================================

# When True  → replay events from LOG_REPLAY_FILE (testing / offline analysis)
# When False → subscribe to live Sysmon events via EvtSubscribe
READ_FROM_FILE = True

LOG_REPLAY_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    '..', 'tests', 'logs_dataset', 'windows-sysmon-T1003.001.txt'
)

# ============================================================================
# GLOBALS
# ============================================================================

detection_pipeline: DetectionPipeline = None
graph_builder = GraphBuilder()

# Self-identification state
_self_pid = os.getpid()
_self_guid = None
_self_guid_lock = threading.Lock()
EDR_IMAGE_MARKER = "EDR_Sysmon_PFA"


# ============================================================================
# SELF-EXCLUSION HELPERS  (unchanged from original)
# ============================================================================

def _is_edr_image(image_path: str) -> bool:
    if not image_path:
        return False
    return EDR_IMAGE_MARKER in image_path.replace("\\", "/")


def _get_field(evt: dict, *keys: str):
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
    if _self_guid is not None:
        event_guid  = _get_field(evt, "guid",        "ProcessGuid")
        parent_guid = _get_field(evt, "parent_guid", "ParentProcessGuid")
        if event_guid == _self_guid or parent_guid == _self_guid:
            return True

    image = _get_field(evt, "image", "Image")
    pid   = _get_field(evt, "pid",   "ProcessId")
    if _is_edr_image(str(image or "")):
        try:
            if int(pid) == _self_pid:
                return True
        except (TypeError, ValueError):
            pass
    return False


# ============================================================================
# SINGLE EVENT-PROCESSING FUNCTION  ← used by BOTH live and replay paths
# ============================================================================

def process_event(evt: dict) -> None:
    """
    Central event handler.  Called identically by:
      - SysmonEventWatcher  (live mode)
      - LogReplayEngine     (replay mode)

    Steps:
      1. Attempt GUID self-discovery (no-op once found)
      2. Drop events originating from this EDR process
      3. Run event through detection pipeline (L1 → L2 → L3 → L4)
      4. Build / update threat graph
      5. Display results and append to results.json
    """
    global detection_pipeline

    if detection_pipeline is None:
        return

    # Self-exclusion
    _try_discover_self_guid(evt)
    if _is_own_event(evt):
        return

    # ── Event header ──────────────────────────────────────────────────────
    event_id     = evt.get('event_id', 0)
    event_type   = evt.get('event_type', 'Unknown')
    timestamp    = evt.get('timestamp', '')
    data         = evt.get('data', {})
    image        = data.get('Image',        evt.get('image', 'N/A'))
    guid         = data.get('ProcessGuid',  evt.get('guid',  'N/A'))
    user         = data.get('User',         evt.get('user',  'N/A'))
    parent_image = data.get('ParentImage', 'N/A')
    command_line = data.get('CommandLine',  'N/A')

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

    # ── Detection pipeline ────────────────────────────────────────────────
    print(f"\n[PROCESSING] Running through detection layers...\n")
    verdict = detection_pipeline.process_event(evt)
    output  = []

    # ── Graph builder ─────────────────────────────────────────────────────
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

    # ── Display layer results ─────────────────────────────────────────────
    print("\n" + "_" * 130)
    print("DETECTION RESULTS FROM ALL LAYERS:")
    print("_" * 130)

    if verdict and verdict.layer_results:
        print(f"  Total Layers with Detections: {len(verdict.layer_results)}\n")
        for result in verdict.layer_results:
            print(result)
            output.append({
                "event":       evt,
                "layer_name":  result.layer_name,
                "threat_level": result.threat_level.name,
                "matches":     result.matches,
                "metadata":    result.metadata,
            })
    else:
        print("  [OK] No detections from any layer (L1, L2, L3, L4)\n")

    # ── Final verdict ─────────────────────────────────────────────────────
    if verdict:
        symbol = {
            'CRITICAL': '[CRITICAL]', 'HIGH': '[HIGH]',
            'MEDIUM':   '[MEDIUM]',   'LOW':  '[LOW]',
            'UNKNOWN':  '[UNKNOWN]',
        }.get(verdict.threat_level.name, '[?]')
        print(f"  [VERDICT] FINAL VERDICT: {symbol} {verdict.threat_level.name}")

    with open("results.json", "a") as f:
        json.dump(output, f, indent=4)

    # TODO: response actions for CRITICAL/HIGH threats
    # TODO: persistent event storage


# ============================================================================
# MAIN
# ============================================================================

def main():
    global detection_pipeline

    print("=" * 70)
    print("EDR SYSTEM - Sysmon Event Monitor")
    print("=" * 70)
    print(f"Mode:             {'LOG REPLAY' if READ_FROM_FILE else 'LIVE SYSMON'}")
    print("Detection layers: L1 (Hash), L2 (Sigma), L3 (YARA), L4 (AI)")
    print(f"Self-exclusion:   PID={_self_pid}, image marker='{EDR_IMAGE_MARKER}'")
    print("Press Ctrl+C to stop.\n")

    detection_pipeline = DetectionPipeline(
        enable_l1=True,
        enable_l2=True,
        enable_l3=False,
        enable_l4=True,
    )

    # ── REPLAY MODE ───────────────────────────────────────────────────────
    if READ_FROM_FILE:
        try:
            from tests.log_replay import LogReplayEngine

            print(f"[INFO] Log-replay mode — reading from: {LOG_REPLAY_FILE}\n")

            engine = LogReplayEngine(
                log_file=LOG_REPLAY_FILE,
                event_callback=process_event,   # ← same function as live mode
            )
            engine.replay(verbose=True)

            # Simple end-of-replay stats
            engine.print_stats()

            # Full pipeline stats
            detection_pipeline.print_stats()

            print("[INFO] Log replay completed. Exiting.\n")
            sys.exit(0)

        except Exception as e:
            print(f"[ERROR] Failed to run log replay engine: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

    # ── LIVE MODE ─────────────────────────────────────────────────────────
    stop_event = threading.Event()
    watcher    = SysmonEventWatcher(callback=process_event, stop_event=stop_event)

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

    signal.signal(signal.SIGINT,  _stop)
    signal.signal(signal.SIGTERM, _stop)

    watcher.start()
    print("[INFO] Listening for live Sysmon events. Press Ctrl+C to stop.\n")

    while not stop_event.is_set():
        time.sleep(0.2)

    if detection_pipeline:
        detection_pipeline.print_stats()


if __name__ == "__main__":
    main()