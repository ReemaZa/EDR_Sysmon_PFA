"""
Log Replay Engine: Replays Sysmon logs from a text file for testing the EDR pipeline.

RESPONSIBILITY:
    - Read Sysmon event logs from a text file
    - Parse each log entry as XML (same format as live events)
    - Feed events to the detection pipeline
    - Generate reports and statistics
    - Support both individual files and batch testing

FEATURES:
    - Format compatibility: Uses same parsing as live events (ingestion.py)
    - Timestamp tracking: Maintains event order and timing
    - Progress reporting: Shows processing status
    - Statistics collection: Generates comprehensive reports
    - Results export: Saves detailed results to JSON/CSV

USAGE:
    from tests.log_replay import LogReplayEngine
    
    engine = LogReplayEngine(log_file='tests/logs/attack_scenario.txt')
    results = engine.replay()
    engine.print_report()
"""

import sys
import os
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.pipeline import DetectionPipeline, ThreatLevel
from src.core.ingestion import parse_sysmon_event


class LogReplayEngine:
    """
    Replays Sysmon event logs from a text file through the detection pipeline.
    
    ARCHITECTURE:
    1. Load log file (text containing XML events, one per line or separated by markers)
    2. Parse each event using the same ingestion.parse_sysmon_event() function
    3. Feed to pipeline.process_event() for detection
    4. Collect results and statistics
    5. Generate comprehensive report
    
    SUPPORTED LOG FORMATS:
    - XML per line: Each line is a complete XML event
    - Delimited XML: Events separated by "---" or custom delimiter
    - Raw XML: Multi-line XML events
    """
    
    def __init__(
        self,
        log_file: str,
        enable_l1: bool = True,
        enable_l2: bool = True,
        enable_l3: bool = True,
        enable_l4: bool = False,
        output_dir: str = 'tests/results',
        event_delimiter: str = '---'
    ):
        """
        Initialize the log replay engine.
        
        Args:
            log_file: Path to the text file containing Sysmon logs
            enable_l1: Enable L1 Hash Reputation layer
            enable_l2: Enable L2 Sigma Rules layer
            enable_l3: Enable L3 YARA Scanner layer
            enable_l4: Enable L4 AI/ML Engine layer
            output_dir: Directory to save results
            event_delimiter: Marker separating events in the log file (or None for line-based)
        """
        self.log_file = log_file
        self.event_delimiter = event_delimiter
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize pipeline with specified layers
        self.pipeline = DetectionPipeline(
            enable_l1=enable_l1,
            enable_l2=enable_l2,
            enable_l3=enable_l3,
            enable_l4=enable_l4
        )
        
        # Results collection
        self.events: List[Dict[str, Any]] = []
        self.verdicts: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []
        self.processing_time: float = 0
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        
    def _read_events_from_file(self) -> List[str]:
        """
        Read raw event strings from the log file.
        
        Supports two formats:
        1. Delimiter-based: Events separated by a marker (e.g., '---')
        2. Line-based: Each line is one event
        
        Returns:
            List of raw event strings (XML)
        """
        if not os.path.exists(self.log_file):
            raise FileNotFoundError(f"Log file not found: {self.log_file}")
        
        with open(self.log_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Try delimiter-based first
        if self.event_delimiter and self.event_delimiter in content:
            events = content.split(self.event_delimiter)
            events = [e.strip() for e in events if e.strip()]
            print(f"[*] Loaded {len(events)} events using delimiter '{self.event_delimiter}'")
            return events
        
        # Fall back to line-based
        events = [line.strip() for line in content.split('\n') if line.strip()]
        print(f"[*] Loaded {len(events)} events (line-based parsing)")
        return events
    
    def _parse_event(self, raw_event: str) -> Optional[Dict[str, Any]]:
        """
        Parse a raw event string using the standard ingestion parser.
        
        This ensures compatibility with live event parsing.
        
        Args:
            raw_event: Raw XML event string
            
        Returns:
            Parsed event dict or None if parsing failed
        """
        try:
            # Use the same parser as live events
            parsed = parse_sysmon_event(raw_event)
            return parsed
        except Exception as e:
            print(f"[!] Parse error on event: {str(e)[:100]}...")
            return None
    
    def replay(self, verbose: bool = True) -> List[Dict[str, Any]]:
        """
        Replay all events through the detection pipeline.
        
        FLOW:
        1. Load events from file
        2. Parse each event
        3. Process through pipeline
        4. Collect verdicts and alerts
        5. Generate statistics
        
        Args:
            verbose: Print progress information
            
        Returns:
            List of detection results
        """
        self.start_time = datetime.now()
        
        # Read raw events from file
        try:
            raw_events = self._read_events_from_file()
        except FileNotFoundError as e:
            print(f"[ERROR] {e}")
            return []
        
        if not raw_events:
            print("[WARNING] No events found in log file")
            return []
        
        print(f"[*] Processing {len(raw_events)} events...")
        print(f"[*] Pipeline configuration: L1={self.pipeline.enable_l1}, "
              f"L2={self.pipeline.enable_l2}, L3={self.pipeline.enable_l3}, "
              f"L4={self.pipeline.enable_l4}\n")
        
        # Process each event
        successful_parses = 0
        for idx, raw_event in enumerate(raw_events, 1):
            # Parse event
            parsed_event = self._parse_event(raw_event)
            
            if parsed_event is None:
                continue
            
            successful_parses += 1
            self.events.append(parsed_event)
            
            # Process through pipeline
            verdict = self.pipeline.process_event(parsed_event)
            
            # Store verdict result
            verdict_dict = {
                'event_index': idx,
                'event_id': parsed_event.get('event_id'),
                'timestamp': parsed_event.get('timestamp'),
                'computer': parsed_event.get('computer'),
                'threat_level': verdict.threat_level.name,
                'is_malicious': verdict.is_malicious(),
                'layer_results': [
                    {
                        'layer': r.layer_name,
                        'threat_level': r.threat_level.name,
                        'matches': r.matches,
                        'metadata': r.metadata
                    }
                    for r in verdict.layer_results
                ]
            }
            self.verdicts.append(verdict_dict)
            
            # Collect alerts
            if verdict.is_malicious():
                self.alerts.append(verdict_dict)
            
            # Progress report
            if verbose and (idx % 100 == 0 or idx == len(raw_events)):
                print(f"[*] Processed {idx}/{len(raw_events)} events "
                      f"({successful_parses} parsed, {len(self.alerts)} alerts)")
        
        self.end_time = datetime.now()
        self.processing_time = (self.end_time - self.start_time).total_seconds()
        
        if verbose:
            print(f"\n[+] Replay complete in {self.processing_time:.2f}s")
        
        return self.verdicts
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Generate comprehensive statistics about the replay session.
        
        Returns:
            Dictionary with statistics
        """
        total_events = len(self.verdicts)
        total_alerts = len(self.alerts)
        
        # Count by threat level
        threat_counts = {
            'CRITICAL': len([a for a in self.alerts if a['threat_level'] == 'CRITICAL']),
            'HIGH': len([a for a in self.alerts if a['threat_level'] == 'HIGH']),
            'MEDIUM': len([a for a in self.alerts if a['threat_level'] == 'MEDIUM']),
            'LOW': len([a for a in self.alerts if a['threat_level'] == 'LOW']),
        }
        
        # Layer detection counts
        layer_counts = {'l1': 0, 'l2': 0, 'l3': 0, 'l4': 0}
        for alert in self.alerts:
            for layer_result in alert['layer_results']:
                layer_name = layer_result['layer'].lower()
                if layer_name in layer_counts:
                    layer_counts[layer_name] += 1
        
        # Event type distribution
        event_type_counts = {}
        for event in self.events:
            event_id = event.get('event_id', 'Unknown')
            event_type_counts[event_id] = event_type_counts.get(event_id, 0) + 1
        
        # Alert rate
        alert_rate = (total_alerts / total_events * 100) if total_events > 0 else 0
        
        # Events per second
        eps = total_events / max(self.processing_time, 0.001)
        
        return {
            'total_events': total_events,
            'total_alerts': total_alerts,
            'alert_rate': f"{alert_rate:.2f}%",
            'threat_counts': threat_counts,
            'layer_detections': layer_counts,
            'event_type_distribution': event_type_counts,
            'processing_time': f"{self.processing_time:.2f}s",
            'events_per_second': f"{eps:.2f}",
            'pipeline_stats': self.pipeline.get_stats()
        }
    
    def export_results_json(self, filename: str = 'replay_results.json') -> str:
        """
        Export detailed results to JSON file.
        
        Args:
            filename: Name of the output file
            
        Returns:
            Path to the created file
        """
        output_path = self.output_dir / filename
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'log_file': self.log_file,
            'statistics': self.get_statistics(),
            'verdicts': self.verdicts,
            'alerts': self.alerts
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        
        return str(output_path)
    
    def export_alerts_csv(self, filename: str = 'alerts.csv') -> str:
        """
        Export alerts to CSV for analysis.
        
        Args:
            filename: Name of the output file
            
        Returns:
            Path to the created file
        """
        import csv
        
        output_path = self.output_dir / filename
        
        if not self.alerts:
            print("[*] No alerts to export")
            return str(output_path)
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'event_index', 'event_id', 'timestamp', 'computer',
                'threat_level', 'layer_results'
            ])
            writer.writeheader()
            
            for alert in self.alerts:
                alert_copy = alert.copy()
                alert_copy['layer_results'] = json.dumps(alert_copy['layer_results'])
                writer.writerow(alert_copy)
        
        return str(output_path)

