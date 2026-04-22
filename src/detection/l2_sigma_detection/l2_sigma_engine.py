from datetime import datetime
import os
import sys
import time
import traceback
from typing import Dict, Any, Optional
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon import sysmon_pipeline

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from sigma_rule_matcher_local.matcher import RuleMatcher
from src.core.utils import DetectionResult, ThreatLevel

# Map event_id to folders
event_id_to_folders = {
    1: {'process_creation': ['process_creation']},
    2: {'file': ['file_change']},
    3: {'network_connection': ['network_connection']},
    4: {'sysmon': ['sysmon_service_change']},
    5: {'process_termination': ['process_termination']},
    6: {'driver_load': ['driver_load']},
    7: {'image_load': ['image_load']},
    8: {'create_remote_thread': ['create_remote_thread']},
    9: {'raw_access_read': ['raw_access_read']},
    10: {'process_access': ['process_access']},
    11: {'file_event': ['file_event']},
    12: {'registry': ['registry_add', 'registry_delete', 'registry_event']},
    13: {'registry': ['registry_set', 'registry_event']},
    14: {'registry': ['registry_rename', 'registry_event']},
    15: {'create_stream_hash': ['create_stream_hash']},
    16: {'sysmon': ['sysmon_config_change']},
    17: {'pipe_created': ['pipe_created']},
    18: {'pipe_created': ['pipe_created']},
    19: {'wmi': ['wmi_event']},
    20: {'wmi': ['wmi_event']},
    21: {'wmi': ['wmi_event']},
    22: {'dns_query': ['dns_query']},
    23: {'file': ['file_delete']},
    24: {'clipboard': ['clipboard_capture']},
    25: {'process_tampering': ['process_tampering']},
    26: {'file': ['file_access']},
    27: {'file': ['file_access']},
    28: {'file': ['file_access']},
    29: {'file': ['file_access']},
    255: {'sysmon': ['sysmon']}
}


class SigmaEngine:
    """Sigma rule matching engine with exception handling."""

    def __init__(self, rules_dir: str = None):
        # Resolve default rules directory relative to this file so loading
        # works regardless of current working directory when the app runs.
        if rules_dir is None:
            base_dir = os.path.dirname(__file__)
            rules_dir = os.path.join(base_dir, 'rules', 'windows')
        self.rules_dir = rules_dir
        self.preloaded_rules = {}
        self.stats = {'total_checks': 0, 'rule_matches': 0}

        try:
            if not os.path.exists(self.rules_dir) or not os.path.isdir(self.rules_dir):
                print(f"[ERROR] Rules directory does not exist: {self.rules_dir}")
            else:
                print(f"[L2-SIGMA] Loading rules from {self.rules_dir}")
                self.pipeline_sysmon = sysmon_pipeline()
                self._load_all_rules()
        except Exception as e:
            print(f"[ERROR] Failed to initialize SigmaEngine: {e}")

    def _load_rules_from_path(self, folder_path: str, categories: list = None):
        rules = []
        try:
            if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
                return rules

            # Subfolders
            subfolders = [d for d in os.listdir(folder_path) if os.path.isdir(os.path.join(folder_path, d))]
            if subfolders and categories:
                for subfolder_name in subfolders:
                    if subfolder_name in categories:
                        subfolder_path = os.path.join(folder_path, subfolder_name)
                        rules.extend(self._load_rules_from_path(subfolder_path))
            else:
                # YAML files directly
                for filename in os.listdir(folder_path):
                    file_path = os.path.join(folder_path, filename)
                    if os.path.isfile(file_path) and file_path.endswith((".yml", ".yaml")):
                        try:
                            with open(file_path, "r", encoding="utf-8") as f:
                                yaml_content = f.read()
                            ruleset = SigmaCollection.from_yaml(yaml_str=yaml_content)
                            for rule in ruleset:
                                transformed_rule = self.pipeline_sysmon.apply(rule)
                                rules.append(RuleMatcher(transformed_rule))
                        except Exception as e:
                            print(f"[ERROR] Failed to load rule {file_path}: {e}")
        except Exception as e:
            print(f"[ERROR] Failed to load rules from path {folder_path}: {e}")
        return rules

    def _load_all_rules(self):
        try:
            for event_id, folders in event_id_to_folders.items():
                self.preloaded_rules[event_id] = []
                for folder_key, categories in folders.items():
                    folder_path = os.path.join(self.rules_dir, folder_key)
                    loaded_rules = self._load_rules_from_path(folder_path, categories)
                    self.preloaded_rules[event_id].extend(loaded_rules)
            print("[L2-SIGMA] Sigma rules loaded successfully")
        except Exception as e:
            print(f"[ERROR] Failed to load all rules: {e}")

    def check_event(self, event: Dict[str, Any]) -> Optional[DetectionResult]:
        """
        Check event against preloaded Sigma rules and return DetectionResult.
        """
        try:
            event = {**event, **event["data"]}
            #print(event)
            matched_rules = []
            metadata = {
                'rules': [],
                'techniques': [],
                'tactics': [],
                #'event_processing_delay': None,
                'total_checks': 0,
                'rules_matched': 0
            }

            # Compute event delay if timestamp exists
            event_ts = event.get('timestamp')
         
            # Iterate over preloaded rules for this event ID
            for matcher in self.preloaded_rules.get(int(event['event_id']), []):
                self.stats['total_checks'] += 1
                try:
                    if matcher.match(event):
                        rule = matcher.rule
                        matched_rules.append(rule.title)
                        metadata['rules'].append(rule.title)
                        for tag in getattr(rule, 'tags', []):
                            tag=str(tag)
                            if tag.startswith("attack.t"):
                                metadata['techniques'].append(tag)   # e.g. attack.t1059
                            elif tag.startswith("attack."):
                                metadata['tactics'].append(tag.replace("attack.", ""))
                except Exception as e:
                    print(f"[ERROR] Rule matching failed: {e}")

            metadata['total_checks'] = self.stats['total_checks']
            metadata['rules_matched'] = len(matched_rules)
            #metadata['event_processing_delay'] = time.time() - event_ts
            # If no matches, return None
            if len(matched_rules) == 0:
                return None

            # Print matches to console for visibility
            try:
                event_summary = f"event_id={event.get('event_id')} timestamp={event.get('timestamp')} computer={event.get('computer') }"
            except Exception:
                event_summary = "event=<unknown>"
            for title in matched_rules:
                print(f"[L2-SIGMA] Match - {event_summary} -> {title}")
            self.stats['rule_matches'] += len(matched_rules)
            return DetectionResult(
                layer_name="L2-Sigma",
                threat_level=ThreatLevel.LOW,
                matches=matched_rules,
                metadata=metadata
            )
        except Exception as e:
            print(traceback.print_exception(e))
            return None

    def get_stats(self) -> Dict[str, Any]:
        return self.stats