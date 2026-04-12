import os
import sys
import json
import hashlib
import traceback
from typing import Dict, Any, Optional

import redis
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon import sysmon_pipeline

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from sigma_rule_matcher_local.matcher import RuleMatcher
from src.core.utils import DetectionResult, ThreatLevel


# ================= REDIS CONFIG =================
REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0


event_id_to_folders = {
    1: {'process_creation': ['process_creation']},
    2: {'file': ['file_change']},
    3: {'network_connection': ['network_connection']},
    4: {'sysmon': ['sysmon_service_change']},
    5: {'process_termination': ['process_termination']},
    6: {'driver_load': ['driver_load']},
    7: {'image_load': ['image_load']},
    8: {'create_remote_thread': ['create_remote_thread']},
    10: {'process_access': ['process_access']},
    11: {'file_event': ['file_event']},
    12: {'registry': ['registry_add', 'registry_delete', 'registry_event']},
    13: {'registry': ['registry_set', 'registry_event']},
    14: {'registry': ['registry_rename', 'registry_event']},
    15: {'create_stream_hash': ['create_stream_hash']},
    17: {'pipe_created': ['pipe_created']},
    18: {'pipe_created': ['pipe_created']},
    22: {'dns_query': ['dns_query']},
    23: {'file': ['file_delete']},
}


class SigmaEngine:

    def __init__(self, rules_dir: str = r"src\detection\l2_sigma_detection\rules\windows"):
        self.rules_dir = rules_dir
        self.preloaded_rules = {}
        self.fields_by_event = {}

        # ✅ Redis connection
        self.redis = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            decode_responses=True,
         
        socket_connect_timeout=5,
        retry_on_timeout=True,
        )
        print(self.redis.ping())

        print("[INIT] Loading Sigma rules...")
        self.pipeline_sysmon = sysmon_pipeline()
        self._load_all_rules()

        print("[INIT] Extracting fields...")
        self.fields_by_event = self._load_fields_from_json("fields.json")
        

    # ================= LOAD RULES =================
    def _load_rules_from_path(self, folder_path, categories=None):
        rules = []

        if not os.path.exists(folder_path):
            return rules

        for filename in os.listdir(folder_path):
            path = os.path.join(folder_path, filename)

            if os.path.isfile(path) and path.endswith((".yml", ".yaml")):
                with open(path, "r", encoding="utf-8") as f:
                    ruleset = SigmaCollection.from_yaml(f.read())

                for rule in ruleset:
                    transformed = self.pipeline_sysmon.apply(rule)
                    rules.append(RuleMatcher(transformed))

        return rules

    def _load_all_rules(self):
        for event_id, folders in event_id_to_folders.items():
            self.preloaded_rules[event_id] = []

            for folder, categories in folders.items():
                path = os.path.join(self.rules_dir, folder)
                rules = self._load_rules_from_path(path, categories)

                # ✅ THIS WAS YOUR BUG BEFORE
                self.preloaded_rules[event_id].extend(rules)

    # ================= FIELD EXTRACTION =================
    def _extract_fields_recursive(self, detection, fields_set):
        for item in detection.detection_items:

            if hasattr(item, "detection_items"):
                self._extract_fields_recursive(item, fields_set)
            else:
                if getattr(item, "field", None):
                    fields_set.add(item.field)
    def _load_fields_from_json(self, path: str) -> Dict[int, Dict[str, Any]]:
        if not os.path.exists(path):
            raise FileNotFoundError(f"[ERROR] fields.json not found at {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        normalized = {}

        for event_id, content in data.items():
            try:
                eid = int(event_id)
                fields = content.get("fields", [])
                normalized[eid] = {"fields": fields}
            except Exception:
                print(f"[WARNING] Invalid event_id in fields.json: {event_id}")

        return normalized
    def export_event_fields(self):
        result = {}

        for event_id, matchers in self.preloaded_rules.items():
            fields_set = set()

            for matcher in matchers:
                rule = matcher.rule

                # explicit fields
                for f in getattr(rule, "fields", []) or []:
                    fields_set.add(f)

                # detection fields
                try:
                    for det in rule.detection.detections.values():
                        self._extract_fields_recursive(det, fields_set)
                except:
                    pass

            result[event_id] = {"fields": list(fields_set)}

        return result

    # ================= HASH =================
    def build_event_hash(self, event: Dict[str, Any]) -> Optional[str]:
        event_id = int(event.get("event_id", -1))
        fields = self.fields_by_event.get(event_id, {}).get("fields", [])

        if not fields:
            return None

        extracted = {}

        for f in fields:
            v = event.get(f)
            if v is not None:
                extracted[f] = str(v).lower()

        canonical = json.dumps(extracted, sort_keys=True)

        return hashlib.sha256(canonical.encode()).hexdigest()

    # ================= REDIS =================
    def is_duplicate(self, event_hash: str) -> bool:
        return self.redis.exists(event_hash)

    def store_event(self, event_hash: str, data: dict):
        self.redis.set(event_hash, json.dumps(data))

    def get_event(self, event_hash: str):
        data = self.redis.get(event_hash)
        return json.loads(data) if data else None

    # ================= MAIN =================
    def check_event(self, event: Dict[str, Any]) -> Optional[DetectionResult]:
       try:
           event = {**event, **event["data"]}

           event_hash = self.build_event_hash(event)
           if not event_hash:
               return None

           # ================= DUPLICATE =================
           if self.is_duplicate(event_hash):
               data = self.get_event(event_hash)

               if not data:
                   return None  # safety

               # 🔁 increment counter
               data["count"] = data.get("count", 1) + 1
               self.store_event(event_hash, data)

               print(f"[DUPLICATE x{data['count']}] {event_hash}")

               # 🔁 rebuild DetectionResult from Redis
               if len(data.get("matches", []))>0:
                    return DetectionResult(
                        layer_name="L2-Sigma",
                        threat_level=ThreatLevel[data.get("threat_level", "").upper()],
                        matches=data.get("matches", []),
                        metadata={
                            **data.get("metadata", {}),
                            "count": data["count"],
                            "source": "redis-cache"
                        }
                    )
               
               return None
            

           # ================= FIRST TIME =================
           matched_rules = []
           metadata = {
               "rules": [],
               "techniques": set(),
               "tactics": set()
           }

           max_severity = ThreatLevel.LOW  # track highest severity

           for matcher in self.preloaded_rules.get(int(event['event_id']), []):
               if matcher.match(event):
                   rule = matcher.rule

                   matched_rules.append(rule.title)
                   metadata["rules"].append(rule.title)

                   # 🎯 extract MITRE tags
                   for tag in getattr(rule, "tags", []):
                       tag = str(tag)
                       if tag.startswith("attack.t"):
                           metadata["techniques"].add(tag)
                       elif tag.startswith("attack."):
                           metadata["tactics"].add(tag.replace("attack.", ""))

                   # 🔥 extract Sigma level
                   level = getattr(rule, "level", None)

                   if level:
                       level_str = str(level).lower()

                       if level_str == "critical":
                           max_severity = ThreatLevel.CRITICAL
                       elif level_str == "high" and max_severity != ThreatLevel.CRITICAL:
                           max_severity = ThreatLevel.HIGH
                       elif level_str == "medium" and max_severity not in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
                           max_severity = ThreatLevel.MEDIUM
                       elif level_str == "low" and max_severity == ThreatLevel.LOW:
                           max_severity = ThreatLevel.LOW
           metadata["techniques"] = list(set(metadata["techniques"]))
           metadata["tactics"] = list(set(metadata["tactics"]))

           
           # ================= STORE =================
           data = {
               "event": event,
               "matches": matched_rules,
               "metadata": metadata,
               "threat_level": max_severity.name,
               "count": 1
           }

           self.store_event(event_hash, data)

           print(f"[NEW] {event_hash}")
           if not matched_rules:
               return None
           return DetectionResult(
               layer_name="L2-Sigma",
               threat_level=max_severity,
               matches=matched_rules,
               metadata={
                   **metadata,
                   "count": 1,
                   "source": "fresh-detection"
               }
           )

       except Exception:
           traceback.print_exc()
           return None