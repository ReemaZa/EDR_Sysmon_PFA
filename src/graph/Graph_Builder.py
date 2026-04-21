import hashlib
import json
import traceback
from datetime import datetime
from typing import Optional
import re
from gqlalchemy import Memgraph


MEMGRAPH_HOST = "localhost"
MEMGRAPH_PORT = 7687


class GraphBuilder:

    def __init__(self):
        self.db = Memgraph(host=MEMGRAPH_HOST, port=MEMGRAPH_PORT)
        self._init_schema()



    def _run(self, query: str, params: dict = {}):
        def extract_info(q: str):
            # detect main action
            action = "UNKNOWN"
            for keyword in ["MERGE", "CREATE", "MATCH", "SET"]:
                if keyword in q.upper():
                    action = keyword
                    break
                
            # detect node labels (e.g., :ProcessInstance, :File)
            nodes = re.findall(r":(\w+)", q)
    
            # detect relationship types (e.g., [:CREATED])
            rels = re.findall(r"\[:(\w+)", q)
    
            return action, nodes, rels
    
        action, nodes, rels = extract_info(query)
    
        try:
            self.db.execute(query, params)
    
            print(f"[OK] {action} | nodes={nodes} | rels={rels}")
            return True
    
        except Exception as e:
            print(f"[FAIL] {action} | nodes={nodes} | rels={rels}")
            print("Error:", str(e))
            return False
    
    def _init_schema(self):
        constraints = [
            "CREATE CONSTRAINT ON (n:ProcessTemplate) ASSERT n.template_hash IS UNIQUE",
            "CREATE CONSTRAINT ON (n:ProcessInstance) ASSERT n.id IS UNIQUE",
            "CREATE CONSTRAINT ON (n:File)            ASSERT n.id IS UNIQUE",
            "CREATE CONSTRAINT ON (n:Network)         ASSERT n.id IS UNIQUE",
            "CREATE CONSTRAINT ON (n:Registry)        ASSERT n.id IS UNIQUE",
            "CREATE CONSTRAINT ON (n:DNS)             ASSERT n.id IS UNIQUE",
            "CREATE CONSTRAINT ON (n:Driver)          ASSERT n.id IS UNIQUE",
            "CREATE CONSTRAINT ON (n:User)            ASSERT n.id IS UNIQUE",
        ]
        for c in constraints:
            try:
                self._run(c)
            except Exception:
                pass

    # ─────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────

    @staticmethod
    def _now() -> str:
        return datetime.utcnow().isoformat()

    @staticmethod
    def _template_hash(image: str, description: str, CommandLine: str) -> str:
        canonical = json.dumps(
            {
                "image":       (image       or "").lower(),
                "description": (description or "").lower(),
                "CommandLine": (CommandLine or "").lower(),
            },
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def _edge_params(detection: Optional[dict]) -> dict:
        if not detection:
            return {"finding_ids": [], "techniques": [], "tactics": [], "total_score": 0}
        return {
            "finding_ids": detection.get("finding_ids", []),
            "techniques":  detection.get("techniques",  []),
            "tactics":     detection.get("tactics",     []),
            "total_score": detection.get("total_score", 0),
        }

    # ─────────────────────────────────────────
    # PROCESS HELPERS
    # ─────────────────────────────────────────

    def _merge_process_instance(
        self,
        guid: str,
        CommandLine: str,
        image: str,
        description: str,
        user: str = "",
    ):
        t_hash = self._template_hash(image, description, CommandLine)
        self._run(
            """
            MERGE (t:ProcessTemplate {template_hash: $t_hash})
            ON CREATE SET
                t.image       = $image,
                t.CommandLine = $CommandLine,
                t.description = $description

            MERGE (u:User {id: $user})

            MERGE (p:ProcessInstance {id: $guid})
            ON CREATE SET
                p.score = 0

            MERGE (p)-[:INSTANCE_OF]->(t)
            MERGE (p)-[:RAN_AS]->(u)
            """,
            {
                "t_hash":      t_hash,
                "image":       image       or "",
                "CommandLine": CommandLine or "",
                "description": description or "",
                "guid":        guid,
                "user":        user        or "UNKNOWN",
            },
        )

    def _update_process_score(self, guid: str, delta: int):
        if not guid or delta == 0:
            return
        self._run(
            """
            MATCH (p:ProcessInstance {id: $guid})
            SET p.score = coalesce(p.score, 0) + $delta
            """,
            {"guid": guid, "delta": delta},
        )

    def _ensure_process(self, event: dict, guid_key: str = "ProcessGuid") -> Optional[str]:
        guid = event.get(guid_key) or event.get("process_guid")
        if not guid:
            return None

        rows = list(
            self.db.execute_and_fetch(
                "MATCH (p:ProcessInstance {id: $guid}) RETURN p.id AS id",
                {"guid": guid},
            )
        )
        if rows:
            return guid

        image       = event.get("Image")       or event.get("image")       or ""
        description = event.get("Description") or event.get("description") or ""
        cmdline     = event.get("CommandLine") or event.get("cmdline")     or ""
        user        = event.get("User")        or event.get("user")        or ""

        self._merge_process_instance(guid, cmdline, image, description, user)
        return guid

    # ─────────────────────────────────────────
    # EVENT HANDLERS
    # ─────────────────────────────────────────

    def handle_event_1(self, event: dict, detection: Optional[dict] = None):
        """ProcessCreate — creates parent and child, links them."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)

        # ── parent ──
        parent_guid = d.get("ParentProcessGuid") or d.get("parent_process_guid")
        if parent_guid:
            self._merge_process_instance(
                guid        = parent_guid,
                CommandLine = d.get("ParentCommandLine") or "",
                image       = d.get("ParentImage")       or "",
                description = "",
            )

        # ── child ──
        child_guid = d.get("ProcessGuid") or d.get("process_guid")
        if child_guid:
            self._merge_process_instance(
                guid        = child_guid,
                CommandLine = d.get("CommandLine")  or "",
                image       = d.get("Image")        or "",
                description = d.get("Description")  or "",
                user        = d.get("User")         or "",
            )

        # ── parent → child edge ──
        if parent_guid and child_guid:
            timestamp = d.get("UtcTime") or d.get("timestamp") or self._now()
            self._run(
                """
                MATCH (parent:ProcessInstance {id: $parent_guid})
                MATCH (child:ProcessInstance  {id: $child_guid})
                MERGE (parent)-[r:CREATED {timestamp: $timestamp}]->(child)
                ON CREATE SET
                    r.finding_ids = $finding_ids,
                    r.techniques  = $techniques,
                    r.tactics     = $tactics,
                    r.total_score = $total_score
                """,
                {
                    "parent_guid": parent_guid,
                    "child_guid":  child_guid,
                    "timestamp":   timestamp,
                    **ep,
                },
            )
            self._update_process_score(parent_guid, ep["total_score"])
            self._update_process_score(child_guid,  ep["total_score"])

    def handle_event_2(self, event: dict, detection: Optional[dict] = None):
        """Timestomp."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        timestamp = d.get("UtcTime") or self._now()

        guid    = self._ensure_process(d)
        file_id = (d.get("TargetFilename") or "").lower()
        if not guid or not file_id:
            return

        self._run("MERGE (:File {id: $id})", {"id": file_id})
        self._run(
            """
            MATCH (i:ProcessInstance {id: $guid})
            MATCH (f:File            {id: $file_id})
            MERGE (i)-[r:TIMESTOMPED {timestamp: $timestamp}]->(f)
            ON CREATE SET r.finding_ids=$finding_ids, r.techniques=$techniques,
                          r.tactics=$tactics, r.total_score=$total_score
            """,
            {"guid": guid, "file_id": file_id, "timestamp": timestamp, **ep},
        )
        self._update_process_score(guid, ep["total_score"])

    def handle_event_3(self, event: dict, detection: Optional[dict] = None):
        """NetworkConnect."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        timestamp = d.get("UtcTime") or self._now()

        guid   = self._ensure_process(d)
        dst_ip = (d.get("DestinationIp") or d.get("destination_ip") or "").lower()
        if not guid or not dst_ip:
            return

        self._run(
            "MERGE (n:Network {id: $ip})",
            {"ip": dst_ip},
        )
        self._run(
            """
            MATCH (i:ProcessInstance {id: $guid})
            MATCH (n:Network         {id: $ip})
            MERGE (i)-[r:CONNECTED {timestamp: $timestamp, port: $port, protocol: $proto}]->(n)
            ON CREATE SET r.finding_ids=$finding_ids, r.techniques=$techniques,
                          r.tactics=$tactics, r.total_score=$total_score
            """,
            {
                "guid":      guid,
                "ip":        dst_ip,
                "timestamp": timestamp,
                "port":      int(d.get("DestinationPort") or 0),
                "proto":     d.get("Protocol") or "",
                **ep,
            },
        )
        self._update_process_score(guid, ep["total_score"])

    def handle_event_6(self, event: dict, detection: Optional[dict] = None):
        """DriverLoad."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        timestamp = d.get("UtcTime") or self._now()

        guid   = self._ensure_process(d)
        sha256 = (d.get("Hashes") or "").split("SHA256=")[-1].split(",")[0].lower()
        image  = (d.get("ImageLoaded") or "").lower()
        if not guid or not sha256:
            return

        self._run(
            "MERGE (drv:Driver {id: $sha256}) ON CREATE SET drv.image = $image",
            {"sha256": sha256, "image": image},
        )
        self._run(
            """
            MATCH (i:ProcessInstance {id: $guid})
            MATCH (drv:Driver        {id: $sha256})
            MERGE (i)-[r:LOADED_DRIVER {timestamp: $timestamp}]->(drv)
            ON CREATE SET r.finding_ids=$finding_ids, r.techniques=$techniques,
                          r.tactics=$tactics, r.total_score=$total_score
            """,
            {"guid": guid, "sha256": sha256, "timestamp": timestamp, **ep},
        )
        self._update_process_score(guid, ep["total_score"])

    def handle_event_7(self, event: dict, detection: Optional[dict] = None):
        """ImageLoad."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        timestamp = d.get("UtcTime") or self._now()

        guid   = self._ensure_process(d)
        sha256 = (d.get("Hashes") or "").split("SHA256=")[-1].split(",")[0].lower()
        image  = (d.get("ImageLoaded") or "").lower()
        if not guid or not sha256:
            return

        self._run(
            "MERGE (img:Driver {id: $sha256}) ON CREATE SET img.image = $image",
            {"sha256": sha256, "image": image},
        )
        self._run(
            """
            MATCH (i:ProcessInstance {id: $guid})
            MATCH (img:Driver        {id: $sha256})
            MERGE (i)-[r:LOADED_IMAGE {timestamp: $timestamp}]->(img)
            ON CREATE SET r.finding_ids=$finding_ids, r.techniques=$techniques,
                          r.tactics=$tactics, r.total_score=$total_score
            """,
            {"guid": guid, "sha256": sha256, "timestamp": timestamp, **ep},
        )
        self._update_process_score(guid, ep["total_score"])

    def handle_event_8(self, event: dict, detection: Optional[dict] = None):
        """CreateRemoteThread."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        timestamp = d.get("UtcTime") or self._now()

        src_guid = self._ensure_process(d, "SourceProcessGuid")
        tgt_guid = self._ensure_process(d, "TargetProcessGuid")
        if not src_guid or not tgt_guid:
            return

        self._run(
            """
            MATCH (src:ProcessInstance {id: $src})
            MATCH (tgt:ProcessInstance {id: $tgt})
            MERGE (src)-[r:INJECTED_THREAD {timestamp: $timestamp, start_function: $fn}]->(tgt)
            ON CREATE SET r.finding_ids=$finding_ids, r.techniques=$techniques,
                          r.tactics=$tactics, r.total_score=$total_score
            """,
            {
                "src": src_guid, "tgt": tgt_guid,
                "timestamp": timestamp,
                "fn": d.get("StartFunction") or "",
                **ep,
            },
        )
        self._update_process_score(src_guid, ep["total_score"])
        self._update_process_score(tgt_guid, ep["total_score"])

    def handle_event_10(self, event: dict, detection: Optional[dict] = None):
        """ProcessAccess."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        timestamp = d.get("UtcTime") or self._now()

        src_guid = self._ensure_process(d, "SourceProcessGUID")
        tgt_guid = self._ensure_process(d, "TargetProcessGUID")
        if not src_guid or not tgt_guid:
            return

        self._run(
            """
            MATCH (src:ProcessInstance {id: $src})
            MATCH (tgt:ProcessInstance {id: $tgt})
            MERGE (src)-[r:ACCESSED_MEMORY {timestamp: $timestamp, access_mask: $mask}]->(tgt)
            ON CREATE SET r.finding_ids=$finding_ids, r.techniques=$techniques,
                          r.tactics=$tactics, r.total_score=$total_score
            """,
            {
                "src": src_guid, "tgt": tgt_guid,
                "timestamp": timestamp,
                "mask": d.get("GrantedAccess") or "",
                **ep,
            },
        )
        self._update_process_score(src_guid, ep["total_score"])

    def handle_event_11(self, event: dict, detection: Optional[dict] = None):
        """FileCreate."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        timestamp = d.get("UtcTime") or self._now()

        guid    = self._ensure_process(d)
        file_id = (d.get("TargetFilename") or "").lower()
        if not guid or not file_id:
            return

        self._run("MERGE (f:File {id: $id})", {"id": file_id})
        self._run(
            """
            MATCH (i:ProcessInstance {id: $guid})
            MATCH (f:File            {id: $file_id})
            MERGE (i)-[r:CREATED_FILE {timestamp: $timestamp}]->(f)
            ON CREATE SET r.finding_ids=$finding_ids, r.techniques=$techniques,
                          r.tactics=$tactics, r.total_score=$total_score,
                          r.size=$size
            """,
            {
                "guid": guid, "file_id": file_id,
                "timestamp": timestamp,
                "size": int(d.get("Size") or 0),
                **ep,
            },
        )
        self._update_process_score(guid, ep["total_score"])

    def _handle_registry(self, event: dict, event_type: str, detection: Optional[dict] = None):
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        timestamp = d.get("UtcTime") or self._now()

        guid   = self._ensure_process(d)
        reg_id = (d.get("TargetObject") or "").lower()
        if not guid or not reg_id:
            return

        self._run("MERGE (reg:Registry {id: $id})", {"id": reg_id})
        self._run(
            """
            MATCH (i:ProcessInstance {id: $guid})
            MATCH (reg:Registry      {id: $reg_id})
            MERGE (i)-[r:MODIFIED_REGISTRY {timestamp: $timestamp, event_type: $etype}]->(reg)
            ON CREATE SET r.finding_ids=$finding_ids, r.techniques=$techniques,
                          r.tactics=$tactics, r.total_score=$total_score
            """,
            {
                "guid": guid, "reg_id": reg_id,
                "timestamp": timestamp,
                "etype": event_type,
                **ep,
            },
        )
        self._update_process_score(guid, ep["total_score"])

    def handle_event_12(self, event, detection=None): self._handle_registry(event, "add",    detection)
    def handle_event_13(self, event, detection=None): self._handle_registry(event, "set",    detection)
    def handle_event_14(self, event, detection=None): self._handle_registry(event, "rename", detection)

    def handle_event_15(self, event: dict, detection: Optional[dict] = None):
        """CreateStreamHash (ADS)."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        timestamp = d.get("UtcTime") or self._now()

        guid    = self._ensure_process(d)
        file_id = (d.get("TargetFilename") or "").lower()
        if not guid or not file_id:
            return

        self._run("MERGE (f:File {id: $id})", {"id": file_id})
        self._run(
            """
            MATCH (i:ProcessInstance {id: $guid})
            MATCH (f:File            {id: $file_id})
            MERGE (i)-[r:WROTE_ADS {timestamp: $timestamp, stream_name: $stream}]->(f)
            ON CREATE SET r.finding_ids=$finding_ids, r.techniques=$techniques,
                          r.tactics=$tactics, r.total_score=$total_score
            """,
            {
                "guid": guid, "file_id": file_id,
                "timestamp": timestamp,
                "stream": d.get("StreamName") or "",
                **ep,
            },
        )
        self._update_process_score(guid, ep["total_score"])

    def handle_event_22(self, event: dict, detection: Optional[dict] = None):
        """DNSQuery."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        timestamp = d.get("UtcTime") or self._now()

        guid  = self._ensure_process(d)
        query = (d.get("QueryName") or "").lower()
        if not guid or not query:
            return

        self._run("MERGE (dns:DNS {id: $q})", {"q": query})
        self._run(
            """
            MATCH (i:ProcessInstance {id: $guid})
            MATCH (dns:DNS           {id: $q})
            MERGE (i)-[r:QUERIED_DNS {timestamp: $timestamp}]->(dns)
            ON CREATE SET r.finding_ids=$finding_ids, r.techniques=$techniques,
                          r.tactics=$tactics, r.total_score=$total_score
            """,
            {"guid": guid, "q": query, "timestamp": timestamp, **ep},
        )
        self._update_process_score(guid, ep["total_score"])

    def handle_event_23(self, event: dict, detection: Optional[dict] = None):
        """FileDelete."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        timestamp = d.get("UtcTime") or self._now()

        guid    = self._ensure_process(d)
        file_id = (d.get("TargetFilename") or "").lower()
        if not guid or not file_id:
            return

        self._run("MERGE (f:File {id: $id})", {"id": file_id})
        self._run(
            """
            MATCH (i:ProcessInstance {id: $guid})
            MATCH (f:File            {id: $file_id})
            MERGE (i)-[r:DELETED {timestamp: $timestamp}]->(f)
            ON CREATE SET r.finding_ids=$finding_ids, r.techniques=$techniques,
                          r.tactics=$tactics, r.total_score=$total_score
            """,
            {"guid": guid, "file_id": file_id, "timestamp": timestamp, **ep},
        )
        self._update_process_score(guid, ep["total_score"])

    # ─────────────────────────────────────────
    # DISPATCHER
    # ─────────────────────────────────────────

    _HANDLERS = {
        1:  "handle_event_1",
        2:  "handle_event_2",
        3:  "handle_event_3",
        6:  "handle_event_6",
        7:  "handle_event_7",
        8:  "handle_event_8",
        10: "handle_event_10",
        11: "handle_event_11",
        12: "handle_event_12",
        13: "handle_event_13",
        14: "handle_event_14",
        15: "handle_event_15",
        22: "handle_event_22",
        23: "handle_event_23",
    }

    def process_event(self, event: dict, detection: Optional[dict] = None):
        try:
            event_id = int(event.get("event_id", -1))
            handler_name = self._HANDLERS.get(event_id)
            if handler_name:
                getattr(self, handler_name)(event, detection)
            else:
                print(f"[GRAPH] No handler for event_id={event_id}")
        except Exception:
            traceback.print_exc()