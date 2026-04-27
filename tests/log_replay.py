"""
Log Replay Engine — pure event source for offline testing.

RESPONSIBILITY:
    - Read Sysmon XML events from a text file
    - Parse each event with the same ingestion.parse_sysmon_event() used live
    - Call the caller-supplied event_callback for every event
      (this is the same process_event() the live watcher calls)
    - Print a concise summary when replay finishes

The engine intentionally owns NO detection logic — all analysis happens inside
the callback, keeping both live and replay paths identical in behaviour.

USAGE:
    from tests.log_replay import LogReplayEngine

    engine = LogReplayEngine(
        log_file='tests/logs/attack_scenario.txt',
        event_callback=agent.process_event,
    )
    engine.replay(verbose=True)
    engine.print_stats()
"""

import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.ingestion import parse_sysmon_event


class LogReplayEngine:
    """
    Replays Sysmon events from a text file, forwarding each event to a callback.

    The callback must have the signature:
        def callback(event: dict) -> None

    It should be the same function used in live mode — typically agent.process_event().
    """

    def __init__(
        self,
        log_file: str,
        event_callback: Callable[[Dict[str, Any]], None],
        event_delimiter: str = '---',
        # Legacy pipeline-toggle kwargs accepted but ignored —
        # pipeline configuration lives in the callback's pipeline, not here.
        enable_l1: bool = True,
        enable_l2: bool = True,
        enable_l3: bool = False,
        enable_l4: bool = False,
    ):
        """
        Args:
            log_file:        Path to the file containing Sysmon XML events.
            event_callback:  Function called for every successfully parsed event.
                             Must be the same handler used in live mode.
            event_delimiter: Token that separates events in the file.
                             Pass None (or empty string) for one-event-per-line format.
        """
        self.log_file       = log_file
        self.event_callback = event_callback
        self.event_delimiter = event_delimiter

        # ── Counters (populated during replay) ────────────────────────────
        self._total_raw: int    = 0   # raw chunks read from file
        self._parsed: int       = 0   # successfully parsed events
        self._parse_errors: int = 0   # chunks that failed to parse
        self._callback_errors: int = 0  # events where callback raised
        self._start_time: Optional[datetime] = None
        self._end_time:   Optional[datetime] = None

    # ── File reading ───────────────────────────────────────────────────────

    def _read_raw_events(self) -> List[str]:
        """Return a list of raw XML strings from the log file."""
        if not os.path.exists(self.log_file):
            raise FileNotFoundError(f"Log file not found: {self.log_file}")

        with open(self.log_file, 'r', encoding='utf-8') as fh:
            content = fh.read()

        if self.event_delimiter and self.event_delimiter in content:
            chunks = [c.strip() for c in content.split(self.event_delimiter) if c.strip()]
            print(f"[Replay] Delimiter '{self.event_delimiter}' found — "
                  f"{len(chunks)} event(s) loaded")
            return chunks

        # Fallback: one event per line
        chunks = [line.strip() for line in content.splitlines() if line.strip()]
        print(f"[Replay] Line-based parsing — {len(chunks)} event(s) loaded")
        return chunks

    # ── Main replay loop ───────────────────────────────────────────────────

    def replay(self, verbose: bool = True) -> None:
        """
        Parse every event in the file and pass it to the callback.

        The callback handles all detection, graphing, and storage — exactly as
        it does for live events.  This method only tracks counts for the
        end-of-replay summary.

        Args:
            verbose: Print a progress line every 100 events.
        """
        self._start_time = datetime.now()

        try:
            raw_events = self._read_raw_events()
        except FileNotFoundError as exc:
            print(f"[Replay][ERROR] {exc}")
            return

        self._total_raw = len(raw_events)

        if self._total_raw == 0:
            print("[Replay][WARNING] No events found in log file.")
            return

        print(f"[Replay] Starting — {self._total_raw} raw event(s) to process\n")

        for idx, raw in enumerate(raw_events, start=1):
            # Parse with the standard ingestion function
            evt = None
            try:
                evt = parse_sysmon_event(raw)
            except Exception as exc:
                print(f"[Replay][WARN] Parse error on event {idx}: {exc}")

            if evt is None:
                self._parse_errors += 1
                continue

            self._parsed += 1

            # Forward to the unified handler
            try:
                self.event_callback(evt)
            except Exception as exc:
                self._callback_errors += 1
                print(f"[Replay][ERROR] Callback raised on event {idx}: {exc}")
                import traceback
                traceback.print_exc()

            # Progress tick
            if verbose and (idx % 100 == 0 or idx == self._total_raw):
                print(f"[Replay] Progress: {idx}/{self._total_raw} raw  |  "
                      f"{self._parsed} parsed  |  {self._parse_errors} skipped")

        self._end_time = datetime.now()

    # ── Stats ──────────────────────────────────────────────────────────────

    def print_stats(self) -> None:
        """Print a concise replay summary to stdout."""
        duration = (
            (self._end_time - self._start_time).total_seconds()
            if self._start_time and self._end_time
            else 0.0
        )
        eps = self._parsed / max(duration, 0.001)

        print("\n" + "=" * 60)
        print("LOG REPLAY — SUMMARY")
        print("=" * 60)
        print(f"  Log file          : {self.log_file}")
        print(f"  Raw chunks read   : {self._total_raw}")
        print(f"  Successfully parsed: {self._parsed}")
        print(f"  Parse failures    : {self._parse_errors}")
        print(f"  Callback errors   : {self._callback_errors}")
        print(f"  Duration          : {duration:.2f}s")
        print(f"  Throughput        : {eps:.1f} events/s")
        print("=" * 60 + "\n")