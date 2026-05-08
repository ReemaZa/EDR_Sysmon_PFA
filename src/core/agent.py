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
from datetime import datetime, timezone

from src.core.event_watcher import SysmonEventWatcher
from src.core.pipeline import DetectionPipeline, ThreatLevel
from src.graph.Graph_Builder import GraphBuilder
from src.graph.Graph_Builder_Batch import GraphBuilderBatch

# ============================================================================
# LOGGING SETUP: Log all console output to both console and file
# ============================================================================
LOG_DIR = "logs"

# ============================================================================
# CONFIGURATION FLAGS
# ============================================================================

REALTIME_REPLAY = True    # True  = simulate live traffic using event timestamps
                           # False = flood replay (as fast as possible)

BATCH_GRAPH   = True       # True  = use UNWIND batch writer
                           # False = original single-event writer

BATCH_SIZE    = 100         # flush when this many events are accumulated
BATCH_TIMEOUT = 1.5       # flush after this many seconds even if batch not full

# ============================================================================
# BATCH STATE
# ============================================================================

_event_batch:     list  = []
_batch_lock             = threading.Lock()
_last_flush_time: float = time.time()

# ============================================================================
# LOGGING
# ============================================================================

os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, f"edr_agent_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

_graph_timing_records: list = []

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
# REPLAY FILE
# ============================================================================

READ_FROM_FILE = True

LOG_REPLAY_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    '..', 'tests', 'logs_datasets','sysmon_credential_dumping.txt'
)

# ============================================================================
# GLOBALS
# ============================================================================

detection_pipeline: DetectionPipeline = None

if BATCH_GRAPH:
    graph_builder = GraphBuilderBatch()
else:
    graph_builder = GraphBuilder()

# Self-identification state
_self_pid        = os.getpid()
_self_guid       = None
_self_guid_lock  = threading.Lock()
EDR_IMAGE_MARKER = "EDR_Sysmon_PFA"


# ============================================================================
# SELF-EXCLUSION HELPERS
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
# REAL-TIME REPLAY
# ============================================================================

def replay_realtime(events: list, callback) -> None:
    """
    Feeds events to callback at their real inter-arrival gaps.
    Simulates live production traffic using historical timestamps.

    Time is rebased so that:
        replay_wall_t0 = time.perf_counter() when first event is fed
        event_t0       = timestamp of first event in the file

    Each event is fed when:
        wall_elapsed >= event_timestamp - event_t0
    """
    if not events:
        return

    # Parse timestamps
    parsed = []
    for evt in events:
        ts_str = evt.get("timestamp", "") or evt.get("data", {}).get("UtcTime", "")
        try:
            ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
        except Exception:
            ts = None
        parsed.append((evt, ts))

    # Drop events with no parseable timestamp
    parsed = [(e, t) for e, t in parsed if t is not None]

    if not parsed:
        print("[REALTIME] No parseable timestamps found — falling back to instant replay")
        for evt in events:
            evt["_arrival_time"] = time.time()
            callback(evt)
        return

    first_ts       = parsed[0][1]
    replay_wall_t0 = time.perf_counter()

    print(f"[REALTIME] Starting real-time replay of {len(parsed)} events")
    print(f"[REALTIME] First event timestamp : {first_ts.isoformat()}")
    print(f"[REALTIME] Simulated duration    : "
          f"{(parsed[-1][1] - first_ts).total_seconds():.1f}s")

    for i, (evt, ts) in enumerate(parsed):

        # How far into the stream this event should fire
        event_offset_sec = (ts - first_ts).total_seconds()

        # How much wall time has elapsed since replay started
        wall_elapsed_sec = time.perf_counter() - replay_wall_t0

        # Sleep if we're ahead of schedule
        sleep_sec = event_offset_sec - wall_elapsed_sec
        if sleep_sec > 0:
            time.sleep(sleep_sec)

        callback(evt)

        if i % 100 == 0:
            wall_elapsed = time.perf_counter() - replay_wall_t0
            print(f"[REALTIME] [{i}/{len(parsed)}] "
                  f"event_offset={event_offset_sec:.1f}s  "
                  f"wall_elapsed={wall_elapsed:.1f}s")


# ============================================================================
# BATCH FLUSH
# ============================================================================

def _flush_batch():
    global _event_batch, _last_flush_time

    with _batch_lock:
        if not _event_batch:
            return

        batch = _event_batch[:]
        _event_batch.clear()

        # ====================================================
        # ONLY TRUE FLUSH TIME
        # ====================================================
        flush_time = time.time()
        _last_flush_time = flush_time

    print(f"[BATCH] flushing {len(batch)} events")

    events = [e for e, _ in batch]
    detections = [d for _, d in batch]

    t0 = time.perf_counter()
    graph_builder.process_event_batch(events, detections)
    """ total_ms = (time.perf_counter() - t0) * 1000

    per_event_ms = total_ms / len(batch)

    # ========================================================
    # RECORD CLEAN METRICS
    # ========================================================
    for evt, _ in batch:

        arrival = evt["_arrival_time"]

        _graph_timing_records.append({
            "event_id": evt.get("event_id", "?"),

            # CORE METRICS ONLY
            "arrival_time": arrival,
            "flush_time": flush_time,

            # DERIVED METRIC (valid now)
            "waiting_time_sec": flush_time - arrival,

            "graph_ms": per_event_ms,
            "batch_size": len(batch),
        })"""


# ============================================================================
# SINGLE EVENT-PROCESSING FUNCTION  ← used by BOTH live and replay paths
# ============================================================================

def process_event(evt: dict) -> None:
    """
    Central event handler. Called identically by:
      - SysmonEventWatcher  (live mode)
      - LogReplayEngine     (flood replay mode)
      - replay_realtime()   (real-time replay mode)

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
    if "_arrival_time" not in evt:
        evt["_arrival_time"] = time.time()

    # ── Event header ──────────────────────────────────────────────────────
    event_id     = evt.get('event_id', 0)
    event_type   = evt.get('event_type', 'Unknown')
    timestamp    = evt.get('timestamp', '')
    data         = evt.get('data', {})
    image        = data.get('Image',       evt.get('image', 'N/A'))
    guid         = data.get('ProcessGuid', evt.get('guid',  'N/A'))
    user         = data.get('User',        evt.get('user',  'N/A'))
    parent_image = data.get('ParentImage', 'N/A')
    command_line = data.get('CommandLine', 'N/A')

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
                    print("wssel lahne")
                    break

        if BATCH_GRAPH:
            # Accumulate — timing is recorded inside _flush_batch
            with _batch_lock:
                _event_batch.append((evt, graph_detection))
                should_flush = (
                    len(_event_batch) >= BATCH_SIZE or
                    (time.time() - _last_flush_time) >= BATCH_TIMEOUT
                )
            if should_flush:
                _flush_batch()
        else:
            # Single-event path — time it directly here
            t0 = time.perf_counter()
            graph_builder.process_event(evt, graph_detection)
            graph_ms = (time.perf_counter() - t0) * 1000
            _graph_timing_records.append({
                "event_id":       str(event_id),
                "graph_ms":       round(graph_ms, 4),
                "batch_total_ms": round(graph_ms, 4),
                "batch_size":     1,
            })

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
                "event":        evt,
                "layer_name":   result.layer_name,
                "threat_level": result.threat_level.name,
                "matches":      result.matches,
                "metadata":     result.metadata,
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


# ============================================================================
# MAIN
# ============================================================================

def main():
    global detection_pipeline

    print("=" * 70)
    print("EDR SYSTEM - Sysmon Event Monitor")
    print("=" * 70)
    print(f"Mode:             {'LOG REPLAY' if READ_FROM_FILE else 'LIVE SYSMON'}")
    print(f"Replay mode:      {'REAL-TIME' if REALTIME_REPLAY else 'FLOOD'}")
    print(f"Graph mode:       {'BATCH' if BATCH_GRAPH else 'SINGLE-EVENT'}")
    if BATCH_GRAPH:
        print(f"Batch size:       {BATCH_SIZE}")
        print(f"Batch timeout:    {BATCH_TIMEOUT}s")
    print("Detection layers: L1 (Hash), L2 (Sigma), L3 (YARA), L4 (AI)")
    print(f"Self-exclusion:   PID={_self_pid}, image marker='{EDR_IMAGE_MARKER}'")
    print("Press Ctrl+C to stop.\n")

    detection_pipeline = DetectionPipeline(
        enable_l1=True,
        enable_l2=True,
        enable_l3=False,
        enable_l4=True,
        enable_l2_hash=True,
    )

    if READ_FROM_FILE:
        try:
            from tests.log_replay import LogReplayEngine

            print(f"[INFO] Log-replay mode — reading from: {LOG_REPLAY_FILE}\n")

            if REALTIME_REPLAY:
                # Collect all events first using a silent dry run
                _collected_events = []
                engine = LogReplayEngine(
                    log_file=LOG_REPLAY_FILE,
                    event_callback=lambda evt: _collected_events.append(evt),
                )
                engine.replay(verbose=False)
                print(f"[REALTIME] Collected {len(_collected_events)} events "
                      f"— starting real-time feed\n")
                replay_realtime(_collected_events, process_event)
            else:
                engine = LogReplayEngine(
                    log_file=LOG_REPLAY_FILE,
                    event_callback=process_event,
                )
                engine.replay(verbose=True)

            # Flush whatever is left in the buffer
            if BATCH_GRAPH:
                _flush_batch()

            engine.print_stats()
            detection_pipeline.print_stats()

            """# ── Save timing JSON ──────────────────────────────────────
            os.makedirs("timing_results", exist_ok=True)
            _graph_timing_path = os.path.join(
                "timing_results",
                
                f"graph_timing_batch_1s.json"
            )

            total     = len(_graph_timing_records)
            avg_graph = (
                round(sum(r["graph_ms"] for r in _graph_timing_records) / total, 4)
                if total else 0.0
            )

            with open(_graph_timing_path, "w", encoding="utf-8") as f:
                json.dump({
                    "records": _graph_timing_records,
                    "summary": {
                        "total":           total,
                        "avg_graph_ms":    avg_graph,
                        "batch_graph":     BATCH_GRAPH,
                        "batch_size":      BATCH_SIZE,
                        "batch_timeout":   BATCH_TIMEOUT,
                        "realtime_replay": REALTIME_REPLAY,
                    }
                }, f, indent=2)

            print(f"[TIMING] Graph timing saved → {_graph_timing_path}")"""
            print("[INFO] Log replay completed. Exiting.\n")

        except Exception as e:
            print(f"[ERROR] Failed to run log replay engine: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

        return  # replay mode never falls into live mode

    else:
        # ── LIVE MODE ────────────────────────────────────────────────────
        stop_event = threading.Event()
        watcher = SysmonEventWatcher(callback=process_event, stop_event=stop_event)

        def _stop(signum, frame):
            print("\n" + "=" * 70)
            print("Stopping watcher...")
            stop_event.set()
            watcher.stop()
            watcher.join(timeout=5)
            if BATCH_GRAPH:
                _flush_batch()
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