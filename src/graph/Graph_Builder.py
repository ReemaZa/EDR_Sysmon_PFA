"""
graph_builder.py  —  Sysmon → Memgraph  (v4.0)
================================================

DESIGN SUMMARY
──────────────
ProcessTemplate
    Key  : sha256(image + parent_image + normalised_cmdline + user)
    Holds: image, parent_image, cmdline, user, description,
           first_seen, last_seen, seen_count, total_score (sum)
    Rule : always upserted on every event, never deleted.
           total_score += effective_score of events belonging to THIS template only.
           Parent template never receives bleed from child events.

ProcessInstance [full]
    Key  : id = Sysmon ProcessGuid
    Holds: id, score (sum), ghost=false, alive, start_time, end_time
    Rule : created only when effective_score > 0 OR rel_type in ALWAYS_STORE.
           No image/cmdline/user — those live on the template.

ProcessInstance [ghost]
    Key  : id = Sysmon ProcessGuid of parent
    Holds: id, ghost=true, score=0, alive=true   — NOTHING ELSE.
    Rule : created when a child instance needs CHILD_OF → parent
           but parent has never scored.
           No image, no start_time, no INSTANCE_OF.
           Promoted in-place when any event fires on this GUID with score > 0.

Ghost promotion
    ON MATCH when ghost=true and new score arrives:
        fill start_time, ghost=false, score += new_score
        wire INSTANCE_OF → template
        propagate score * 0.4 to all existing CHILD_OF children

CHILD_OF
    Always instance → instance (ghost or full).
    Only created from Event-1 (ProcessCreate) — OS spawn relationship.
    Never from injection, memory access, or any other edge type.

Score inheritance
    child.score += parent.score * 0.4
    Applied immediately when CHILD_OF is created and parent.score > 0.
    Applied retroactively to all children when ghost is promoted.
    Injection / memory access edges do NOT create CHILD_OF and do NOT inherit.

Edge storage gate
    Store when: process.score > 0  OR  rel_type in ALWAYS_STORE
    Skip when : process.score = 0  AND rel_type NOT in ALWAYS_STORE
                → only bump template (seen_count++, last_seen)

ALWAYS_STORE = {INJECTED_THREAD, ACCESSED_MEMORY, TAMPERED, TIMESTOMPED, WROTE_ADS}

Edge compression
    MERGE key = edge_hash = sha256(src_id + rel_type + dst_id + alert_sig)
    alert_sig  = sha256(sorted(techniques + tactics))
    ON CREATE: first_seen, last_seen, count=1, total_score=score, finding_ids, ...
    ON MATCH : last_seen, count++, total_score += score, finding_ids appended (cap 20)
    Timestamp NEVER in MERGE key.

Sigma score scale: 1–4 integers.
Base weights (floor): effective_score = max(sigma_score, base_weight)
    INJECTED_THREAD  4
    ACCESSED_MEMORY  3
    TAMPERED         3
    TIMESTOMPED      2
    WROTE_ADS        2
    CREATED          1
    CONNECTED        1
    all others       0  (use sigma score directly)

Score destinations per event:
    edge.total_score     += effective_score
    instance.score       += effective_score
    template.total_score += effective_score   (own template only, no parent bleed)
"""

import hashlib
import json
import re
import traceback
from datetime import datetime
from typing import Optional

from gqlalchemy import Memgraph

MEMGRAPH_HOST = "localhost"
MEMGRAPH_PORT = 7687

# Sigma scale 1–4
EDGE_WEIGHTS: dict[str, int] = {
    "INJECTED_THREAD": 4,
    "ACCESSED_MEMORY": 3,
    "TAMPERED":        3,
    "TIMESTOMPED":     2,
  
  
}

ALWAYS_STORE: set[str] = {
    #"INJECTED_THREAD",
    #"ACCESSED_MEMORY",
    #"TAMPERED",
    #"TIMESTOMPED"
    
  
    
}

PARENT_INHERITANCE = 0.4
FINDING_IDS_CAP    = 20


# ══════════════════════════════════════════════════════════════════════════════
class GraphBuilder:

    def __init__(self):
        self.db = Memgraph(host=MEMGRAPH_HOST, port=MEMGRAPH_PORT)
        self._init_schema()

    # ─────────────────────────────────────────
    # DB LAYER
    # ─────────────────────────────────────────

    def _run(self, query: str, params: dict = {}) -> bool:
        action = "UNKNOWN"
        for kw in ("MERGE", "CREATE", "MATCH", "SET", "DELETE"):
            if kw in query.upper():
                action = kw
                break
        nodes = re.findall(r":(\w+)", query)
        rels  = re.findall(r"\[:(\w+)", query)
        try:
            self.db.execute(query, params)
            print(f"[OK]   {action} | nodes={nodes} | rels={rels}")
            return True
        except Exception as e:
            print(f"[FAIL] {action} | nodes={nodes} | rels={rels} | {e}")
            return False

    def _fetch(self, query: str, params: dict = {}) -> list[dict]:
        try:
            return list(self.db.execute_and_fetch(query, params))
        except Exception as e:
            print(f"[FETCH FAIL] {e}")
            return []

    def _init_schema(self):
        for c in [
            # ADD alongside existing constraints
            "CREATE CONSTRAINT ON (n:Image) ASSERT n.id IS UNIQUE",
            "CREATE CONSTRAINT ON (n:ProcessTemplate) ASSERT n.template_hash IS UNIQUE",
            "CREATE CONSTRAINT ON (n:ProcessInstance) ASSERT n.id             IS UNIQUE",
            "CREATE CONSTRAINT ON (n:File)            ASSERT n.id             IS UNIQUE",
            "CREATE CONSTRAINT ON (n:Network)         ASSERT n.id             IS UNIQUE",
            "CREATE CONSTRAINT ON (n:Registry)        ASSERT n.id             IS UNIQUE",
            "CREATE CONSTRAINT ON (n:DNS)             ASSERT n.id             IS UNIQUE",
            "CREATE CONSTRAINT ON (n:Driver)          ASSERT n.id             IS UNIQUE",
        ]:
            try:
                self._run(c)
            except Exception:
                pass

    # ─────────────────────────────────────────
    # HASH HELPERS
    # ─────────────────────────────────────────

    @staticmethod
    def _now() -> str:
        return datetime.utcnow().isoformat()

    @staticmethod
    def _h(obj) -> str:
        return hashlib.sha256(
            json.dumps(obj, sort_keys=True, ensure_ascii=True).encode()
        ).hexdigest()

    @classmethod
    def _template_hash(cls, image: str, parent_image: str,
                       cmdline: str, user: str) -> str:
        def norm(cmd: str) -> str:
            cmd = cmd.lower().strip()
            cmd = re.sub(r"[a-z]:\\[^\s]+\\", "", cmd)
            cmd = re.sub(r"\s+", " ", cmd)
            return cmd[:256]
        return cls._h({
            "image":        (image        or "").lower(),
            "parent_image": (parent_image or "").lower(),
            "cmdline":      norm(cmdline  or ""),
            "user":         (user         or "").lower(),
        })

    @classmethod
    def _edge_hash(cls, src_id: str, rel_type: str, dst_id: str,
                   techniques: list, tactics: list) -> str:
        sig = cls._h({
            "techniques": sorted(techniques),
            "tactics":    sorted(tactics),
        })
        return cls._h({
            "src":       src_id,
            "rel":       rel_type,
            "dst":       dst_id,
            "alert_sig": sig,
        })

    @staticmethod
    def _edge_params(detection: Optional[dict]) -> dict:
        if not detection:
            return {
                "finding_ids": [],
                "techniques":  [],
                "tactics":     [],
                "total_score": 0,
            }
        return {
            "finding_ids": detection.get("finding_ids", []),
            "techniques":  detection.get("techniques",  []),
            "tactics":     detection.get("tactics",     []),
            "total_score": int(detection.get("total_score", 0)),
        }

    @staticmethod
    def _effective_score(sigma_score: int, rel_type: str) -> int:
        base = EDGE_WEIGHTS.get(rel_type, 0)
        return max(sigma_score, base)

    # ─────────────────────────────────────────
    # TEMPLATE
    # ─────────────────────────────────────────

    def _upsert_template(
        self,
        image:        str,
        parent_image: str,
        cmdline:      str,
        user:         str,
        description:  str = "",
        timestamp:    str = "",
        score:        int = 0,
    ) -> str:
        """
        Always upsert. Returns template_hash.
        total_score accumulates only scores from events belonging to THIS template.
        Parent template never receives child score bleed.
        """
        t_hash = self._template_hash(image, parent_image, cmdline, user)
        ts     = timestamp or self._now()
        cmdline=re.sub(
        r'(?i)(-encodedcommand|-enc)\s+[A-Za-z0-9+/=]{20,}',
        r'\1 [BASE64-ENCODED-PAYLOAD]',
        cmdline
    )
        self._run(
            """
            MERGE (t:ProcessTemplate {template_hash: $t_hash})
            ON CREATE SET
                t.image        = $image,
                t.parent_image = $parent_image,
                t.cmdline      = $cmdline,
                t.user         = $user,
                t.description  = $description,
                t.seen_count   = 1,
                t.total_score  = $score,
                t.first_seen   = $ts,
                t.last_seen    = $ts
            ON MATCH SET
                t.seen_count  = t.seen_count + 1,
                t.last_seen   = $ts,
                t.total_score = t.total_score + $score
            """,
            {
                "t_hash":       t_hash,
                "image":        (image        or "").lower(),
                "parent_image": (parent_image or "").lower(),
                "cmdline":      (cmdline      or "").lower(),
                "user":         (user         or "").lower(),
                "description":  (description  or "").lower(),
                "score":        score,
                "ts":           ts,
            },
        )
        return t_hash

    # ─────────────────────────────────────────
    # INSTANCE QUERIES
    # ─────────────────────────────────────────

    def _instance_exists(self, guid: str) -> bool:
        return bool(self._fetch(
            "MATCH (p:ProcessInstance {id: $guid}) RETURN p.id AS id",
            {"guid": guid},
        ))

    def _get_score(self, guid: str) -> int:
        rows = self._fetch(
            "MATCH (p:ProcessInstance {id: $guid}) RETURN p.score AS score",
            {"guid": guid},
        )
        return int(rows[0]["score"] or 0) if rows else 0

    def _is_ghost(self, guid: str) -> bool:
        rows = self._fetch(
            "MATCH (p:ProcessInstance {id: $guid}) RETURN p.ghost AS ghost",
            {"guid": guid},
        )
        return bool(rows[0]["ghost"]) if rows else False

    # ─────────────────────────────────────────
    # GHOST CREATION
    # ─────────────────────────────────────────

    def _create_ghost(self, guid: str):
        """
        Minimal placeholder. Only id, ghost=true, score=0, alive=true.
        No image, no start_time, no INSTANCE_OF.
        Children know the parent image via their own template's parent_image field.
        """
        self._run(
            """
            MERGE (p:ProcessInstance {id: $guid})
            ON CREATE SET
                p.ghost = true,
                p.score = 0,
                p.alive = true
            """,
            {"guid": guid},
        )

    # ─────────────────────────────────────────
    # FULL INSTANCE CREATION / GHOST PROMOTION
    # ─────────────────────────────────────────

    def _create_or_promote_instance(
        self,
        guid:         str,
        image:        str,
        parent_image: str,
        cmdline:      str,
        user:         str,
        description:  str,
        score:        int,
        timestamp:    str,
        t_hash: str,
        pid: str
    ) -> str:
        if not guid:
            return ""
        if not t_hash:
            t_hash    = self._template_hash(image, parent_image, cmdline, user)
        ts        = timestamp or self._now()
        was_ghost = self._is_ghost(guid)  # read ghost state BEFORE any write

        self._run(
            """
            MERGE (p:ProcessInstance {id: $guid})
            ON CREATE SET
                p.score      = $score,
                p.alive      = true,
                p.pid        = $pid,
                p.start_time = $ts
            ON MATCH SET
                p.score      = p.score + $score
                
            """,
            {"guid": guid, "score": score, "ts": ts,"pid": pid},
        )

        self._run(
            """
            MATCH (p:ProcessInstance {id: $guid})
            WHERE NOT EXISTS((p)-[:INSTANCE_OF]->())
            MATCH (t:ProcessTemplate {template_hash: $t_hash})
            MERGE (p)-[:INSTANCE_OF]->(t)
            """,
            {"guid": guid, "t_hash": t_hash},
        )

        return guid

    # ─────────────────────────────────────────
    # SCORE PROPAGATION
    # ─────────────────────────────────────────

    def _propagate_to_children(self, parent_guid: str, parent_score: int):
        """
        Push parent_score * 0.4 to all direct CHILD_OF children.
        Called on ghost promotion only.
        """
        children = self._fetch(
            """
            MATCH (c:ProcessInstance)-[:CHILD_OF]->(p:ProcessInstance {id: $guid})
            RETURN c.id AS cid
            """,
            {"guid": parent_guid},
        )
        delta = int(parent_score * PARENT_INHERITANCE)
        if delta <= 0:
            return
        for c in children:
            self._run(
                "MATCH (p:ProcessInstance {id: $guid}) SET p.score = p.score + $d",
                {"guid": c["cid"], "d": delta},
            )

    def _add_score(self, guid: str, delta: int):
        if not guid or delta == 0:
            return
        self._run(
            "MATCH (p:ProcessInstance {id: $guid}) SET p.score = p.score + $d",
            {"guid": guid, "d": delta},
        )

    # ─────────────────────────────────────────
    # PARENT CHAIN
    # ─────────────────────────────────────────

    def _ensure_parent_and_link(
        self,
        child_guid:   str,
        parent_guid:  str,
        timestamp:    str,
    ):
        """
        Guarantees parent exists (full or ghost) then wires CHILD_OF.
        Applies immediate score inheritance if parent.score > 0.
        Called only from Event-1 (ProcessCreate).
        No other event type creates CHILD_OF.
        """
        if not parent_guid or not child_guid:
            return

   

        # wire CHILD_OF (idempotent)
        self._run(
            """
            MATCH (child:ProcessInstance  {id: $child_guid})
            MATCH (parent:ProcessInstance {id: $parent_guid})
            MERGE (child)-[:CHILD_OF]->(parent)
            """,
            {"child_guid": child_guid, "parent_guid": parent_guid},
        )

      
    
    # ─────────────────────────────────────────
    # EDGE STORAGE GATE
    # ─────────────────────────────────────────

    def _should_store_edge(self, rel_type: str, process_score: int) -> bool:
        return process_score > 0 
    #or rel_type in ALWAYS_STORE

    # ─────────────────────────────────────────
    # GENERIC EDGE UPSERT
    # ─────────────────────────────────────────

    def _merge_edge(
        self,
        src_id:       str,
        src_label:    str,
        rel_type:     str,
        dst_id:       str,
        dst_label:    str,
        ep:           dict,
        eff_score:    int,
        timestamp:    str,
        extra_create: dict = {},
    ):
        """
        Compressed edge upsert.
        MERGE key = edge_hash (timestamp excluded).
        total_score is a running SUM, not max.
        """
        e_hash    = self._edge_hash(
            src_id, rel_type, dst_id, ep["techniques"], ep["tactics"]
        )
        extra_set = "".join(f", r.{k} = ${k}" for k in extra_create)

        self._run(
            f"""
            MATCH (src:{src_label} {{id: $src_id}})
            MATCH (dst:{dst_label} {{id: $dst_id}})
            MERGE (src)-[r:{rel_type} {{edge_hash: $e_hash}}]->(dst)
            ON CREATE SET
                r.first_seen   = $ts,
                r.last_seen    = $ts,
                r.count        = 1,
                r.total_score  = $score,
                r.finding_ids  = $fids,
                r.techniques   = $techs,
                r.tactics      = $tacs
                {extra_set}
            ON MATCH SET
                r.last_seen   = $ts,
                r.count       = r.count + 1,
                r.total_score = r.total_score + $score,
                r.finding_ids = CASE
                    WHEN size(r.finding_ids) < {FINDING_IDS_CAP}
                    THEN r.finding_ids + $fids
                    ELSE r.finding_ids
                END
            """,
            {
                "src_id": src_id,
                "dst_id": dst_id,
                "e_hash": e_hash,
                "ts":     timestamp,
                "score":  eff_score,
                "fids":   ep["finding_ids"][:FINDING_IDS_CAP],
                "techs":  ep["techniques"],
                "tacs":   ep["tactics"],
                **extra_create,
            },
        )

    # ─────────────────────────────────────────
    # EVENT HANDLERS
    # ─────────────────────────────────────────

    def handle_event_1(self, event: dict, detection: Optional[dict] = None):
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        parent_guid  = d.get("ParentProcessGuid") or ""
        child_guid   = d.get("ProcessGuid")       or ""
        parent_image = (d.get("ParentImage")       or "").lower()
        child_image  = (d.get("Image")             or "").lower()
        parent_cmd   = d.get("ParentCommandLine")  or ""
        child_cmd    = d.get("CommandLine")        or ""
        description  = d.get("Description")        or ""
        user         = (d.get("User")              or "").lower()
        parent_user  = (d.get("ParentUser")        or "").lower()  # ← separate field

        eff = ep["total_score"]

        # parent gets its own user, not the child's
        p_hash=self._upsert_template(parent_image, "", parent_cmd, parent_user, "", ts, 0)
        t_hash=self._upsert_template(child_image, parent_image, child_cmd, user,
                              description, ts, eff)
        child_pid  = int(d.get("ProcessId") or 0)  or None
        parent_pid = int(d.get("ParentProcessId") or 0)  or None
        
        if parent_guid:
            self._create_or_promote_instance(
                guid=parent_guid, image=parent_image,
                parent_image="", cmdline=parent_cmd,
                user=parent_user, description="",
                score=0, timestamp=ts, t_hash=p_hash,
                pid=parent_pid  # 👈 ADD
            )
        parent_score = self._get_score(parent_guid)
        delta = int(parent_score * PARENT_INHERITANCE)

        eff=eff+delta
        #if eff > 0:
        if child_guid:
            self._create_or_promote_instance(
                guid=child_guid, image=child_image,
                parent_image=parent_image, cmdline=child_cmd,
                user=user, description=description,
                score=eff, timestamp=ts,t_hash=t_hash,
                pid=child_pid   # 👈 ADD
            )
        

       
    
        self._ensure_parent_and_link(child_guid=child_guid,parent_guid=parent_guid,timestamp=ts)
        self._merge_edge(
                    src_id=parent_guid, src_label="ProcessInstance",
                    rel_type="CREATED",
                    dst_id=child_guid,  dst_label="ProcessInstance",
                    ep=ep, eff_score=eff-delta, timestamp=ts,
                )
                # ← _add_score removed here; instance score already set in _create_or_promote_instance

    def handle_event_2(self, event: dict, detection: Optional[dict] = None):
        """FileCreateTime — Timestomp."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()
    
        guid    = d.get("ProcessGuid")      or ""
        file_id = (d.get("TargetFilename")  or "").lower()
        image   = (d.get("Image")           or "").lower()
        cmd     = d.get("CommandLine")      or ""
        user    = (d.get("User")            or "").lower()
        if not guid or not file_id:
            return
    
        #eff       = self._effective_score(ep["total_score"], "TIMESTOMPED")
        eff=ep["total_score"]
        cur_score = self._get_score(guid)
        t_hash=self._upsert_template(image, "", cmd, user, "", ts, eff)
        #if not (eff+cur_score)> 0:
            
        #    return
        pid  = int(d.get("ProcessId") or 0) or None
        
        
        self._create_or_promote_instance(
            guid=guid, image=image, parent_image="",
            cmdline=cmd, user=user, description="",
            score=eff, timestamp=ts,t_hash=t_hash,pid=pid
        )
        sha256 = (d.get("Hashes") or "").split("SHA256=")[-1].split(",")[0].lower() if "SHA256=" in (d.get("Hashes") or "") else ""
        self._run("""
            MERGE (f:File {id: $id})
            ON CREATE SET f.sha256 = $sha256
            ON MATCH SET  f.sha256 = $sha256
        """, {"id": file_id, "sha256": sha256})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="TIMESTOMPED",
            dst_id=file_id, dst_label="File",
            ep=ep, eff_score=eff, timestamp=ts,
        )
        #self._add_score(guid, eff)

    def handle_event_3(self, event: dict, detection: Optional[dict] = None):
        """NetworkConnect. Stored only when process.score > 0."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid   = d.get("ProcessGuid") or ""
        dst_ip = (d.get("DestinationIp") or "").lower()
        image  = (d.get("Image")         or "").lower()
        cmd    = d.get("CommandLine")    or ""
        user   = (d.get("User")          or "").lower()
        if not guid or not dst_ip:
            return

        eff       = ep["total_score"]
        cur_score = self._get_score(guid)
        t_hash=self._upsert_template(image, "", cmd, user, "", ts, eff)
        #if not (eff+cur_score)> 0:
           
        #    return

        pid  = int(d.get("ProcessId") or 0) or None
        pid  = int(d.get("ProcessId") or 0) or None
        
        self._create_or_promote_instance(
            guid=guid, image=image, parent_image="",
            cmdline=cmd, user=user, description="",
            score=eff, timestamp=ts,t_hash=t_hash,pid=pid
        )
        self._run("MERGE (n:Network {id: $ip})", {"ip": dst_ip})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="CONNECTED",
            dst_id=dst_ip, dst_label="Network",
            ep=ep, eff_score=eff, timestamp=ts,
            extra_create={
                "port":     int(d.get("DestinationPort") or 0),
                "protocol": d.get("Protocol") or "",
            },
        )
        #self._add_score(guid, eff)

    def handle_event_6(self, event: dict, detection: Optional[dict] = None):
        """DriverLoad. Stored only when process.score > 0."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid      = d.get("ProcessGuid") or ""
        sha256    = (d.get("Hashes") or "").split("SHA256=")[-1].split(",")[0].lower()
        img_loaded = (d.get("ImageLoaded") or "").lower()
        image     = (d.get("Image")        or "").lower()
        user      = (d.get("User")         or "").lower()
        if not guid or not sha256:
            return

        eff       = ep["total_score"]
        cur_score = self._get_score(guid)
        t_hash=self._upsert_template(image, "", "", user, "", ts, eff)
        #if not (eff+cur_score)> 0:
          
        #    return

        pid  = int(d.get("ProcessId") or 0) or None
        self._create_or_promote_instance(
            guid=guid, image=image, parent_image="",
            cmdline="", user=user, description="",
            score=eff, timestamp=ts,t_hash=t_hash,pid=pid
        )
        self._run(
    "MERGE (drv:Driver {id: $s}) ON CREATE SET drv.path = $img",
    {"s": sha256, "img": img_loaded},
)
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="LOADED_DRIVER",
            dst_id=sha256, dst_label="Driver",
            ep=ep, eff_score=eff, timestamp=ts,
        )
        #self._add_score(guid, eff)

    def handle_event_7(self, event: dict, detection: Optional[dict] = None):
        """ImageLoad. Stored only when process.score > 0."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid       = d.get("ProcessGuid") or ""
        sha256     = (d.get("Hashes") or "").split("SHA256=")[-1].split(",")[0].lower()
        img_loaded = (d.get("ImageLoaded") or "").lower()
        image      = (d.get("Image")       or "").lower()
        user       = (d.get("User")        or "").lower()
        if not guid or not sha256:
            return

        eff       = ep["total_score"]
        cur_score = self._get_score(guid)
        t_hash=self._upsert_template(image, "", "", user, "", ts, eff)
        #if not (eff+cur_score)> 0:
            
        #    return

        pid  = int(d.get("ProcessId") or 0) or None
        self._create_or_promote_instance(
            guid=guid, image=image, parent_image="",
            cmdline="", user=user, description="",
            score=eff, timestamp=ts,t_hash=t_hash,pid=pid
        )
        self._run(
    "MERGE (img:Image {id: $s}) ON CREATE SET img.path = $i",
    {"s": sha256, "i": img_loaded},
)
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="LOADED_IMAGE",
            dst_id=sha256, dst_label="Image",
            ep=ep, eff_score=eff, timestamp=ts,
        )
        #self._add_score(guid, eff)

    def handle_event_8(self, event: dict, detection: Optional[dict] = None):
        """
        CreateRemoteThread. ALWAYS_STORE.
        Both source and target get scored independently.
        NO CHILD_OF created — injection is not a spawn relationship.
        NO inheritance between source and target.
        """
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        src_guid  = d.get("SourceProcessGuid")  or d.get("SourceProcessGuid") or ""
        tgt_guid  = d.get("TargetProcessGuid")  or d.get("TargetProcessGUID") or ""
        src_image = (d.get("SourceImage") or "").lower()
        tgt_image = (d.get("TargetImage") or "").lower()
        src_user  = (d.get("SourceUser")  or "").lower()
        tgt_user  = (d.get("TargetUser")  or "").lower()
        if not src_guid or not tgt_guid:
            return

        eff = ep["total_score"]
        src_cur_score = self._get_score(src_guid)
        tgt_cur_score = self._get_score(tgt_guid)

        # Source - with gate check
        src_should_store =  (eff+src_cur_score)> 0  or  (eff+tgt_cur_score)> 0
        src_t_hash = self._upsert_template(src_image, "", "", src_user, "", ts, eff )
        tgt_t_hash = self._upsert_template(tgt_image, "", "", tgt_user, "", ts, eff )
        #if src_should_store:
        src_pid = int(d.get("SourceProcessId") or 0) or None
        tgt_pid = int(d.get("TargetProcessId") or 0)   or None
        self._create_or_promote_instance(
                guid=src_guid, image=src_image, parent_image="",
                cmdline="", user=src_user, description="",
                score=eff, timestamp=ts, t_hash=src_t_hash,pid=src_pid
            )
          
        # Target - with gate check
        
            
        
        self._create_or_promote_instance(
            guid=tgt_guid, image=tgt_image, parent_image="",
                cmdline="", user=tgt_user, description="",
                score=eff, timestamp=ts, t_hash=tgt_t_hash,pid=tgt_pid
            )

            # Edge only if BOTH instances exist
        if self._instance_exists(src_guid) and self._instance_exists(tgt_guid):
                self._merge_edge(
                    src_id=src_guid, src_label="ProcessInstance",
                    rel_type="INJECTED_THREAD",
                    dst_id=tgt_guid, dst_label="ProcessInstance",
                    ep=ep, eff_score=eff, timestamp=ts,
                    extra_create={"start_function": d.get("StartFunction") or ""},
                )
    def handle_event_10(self, event: dict, detection: Optional[dict] = None):
        """
        ProcessAccess. ALWAYS_STORE.
        Both source and target get scored independently.
        NO CHILD_OF. NO inheritance.
        """
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        src_guid  = d.get("SourceProcessGuid")  or d.get("SourceProcessGUID") or ""
        tgt_guid  = d.get("TargetProcessGuid")  or d.get("TargetProcessGUID")or ""
        src_image = (d.get("SourceImage") or "").lower()
        tgt_image = (d.get("TargetImage") or "").lower()
        src_user  = (d.get("SourceUser")  or "").lower()
        tgt_user  = (d.get("TargetUser")  or "").lower()
        if not src_guid or not tgt_guid:
            return

        eff = ep["total_score"]
        src_cur_score = self._get_score(src_guid)
        tgt_cur_score = self._get_score(tgt_guid)
        src_t_hash = self._upsert_template(src_image, "", "", src_user, "", ts, eff )
        tgt_t_hash = self._upsert_template(tgt_image, "", "", tgt_user, "", ts, eff )
        # Source - with gate check
        #src_should_store =  (eff+src_cur_score)> 0 or (eff+tgt_cur_score)> 0
        
        #if src_should_store:
        src_pid = int(d.get("SourceProcessId") or 0) or None
        tgt_pid = int(d.get("TargetProcessId") or 0)   or None
        self._create_or_promote_instance(
                guid=src_guid, image=src_image, parent_image="",
                cmdline="", user=src_user, description="",
                score=eff, timestamp=ts, t_hash=src_t_hash,pid=src_pid
            )

        # Target - with gate check
            
            
            
        self._create_or_promote_instance(
                    guid=tgt_guid, image=tgt_image, parent_image="",
                    cmdline="", user=tgt_user, description="",
                    score=eff, timestamp=ts, t_hash=tgt_t_hash,pid=tgt_pid
                )

            # Edge only if BOTH instances exist
        if self._instance_exists(src_guid) and self._instance_exists(tgt_guid):
                self._merge_edge(
                    src_id=src_guid, src_label="ProcessInstance",
                    rel_type="ACCESSED_MEMORY",
                    dst_id=tgt_guid, dst_label="ProcessInstance",
                    ep=ep, eff_score=eff, timestamp=ts,
                    extra_create={"access_mask": d.get("GrantedAccess") or ""},
                )

    def handle_event_11(self, event: dict, detection: Optional[dict] = None):
        """FileCreate. Stored only when process.score > 0."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid    = d.get("ProcessGuid") or ""
        file_id = (d.get("TargetFilename") or "").lower()
        sha256    = (d.get("Hashes") or "").split("SHA256=")[-1].split(",")[0].lower() if "SHA256=" in (d.get("Hashes") or "") else ""
        image   = (d.get("Image")          or "").lower()
        cmd     = d.get("CommandLine")     or ""
        user    = (d.get("User")           or "").lower()
        if not guid or not file_id:
            return

        eff       = ep["total_score"]
        cur_score = self._get_score(guid)
        t_hash=self._upsert_template(image, "", cmd, user, "", ts, eff)
        #if not (eff+cur_score)> 0:
            
        #    return
        pid = int(d.get("ProcessId") or 0) or None
      
        self._create_or_promote_instance(
            guid=guid, image=image, parent_image="",
            cmdline=cmd, user=user, description="",
            score=eff, timestamp=ts,t_hash=t_hash,pid=pid
        )
        self._run("""
    MERGE (f:File {id: $id})
    ON CREATE SET f.sha256 = $sha256
    ON MATCH SET  f.sha256 = $sha256
""", {"id": file_id, "sha256": sha256})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="CREATED_FILE",
            dst_id=file_id, dst_label="File",
            ep=ep, eff_score=eff, timestamp=ts,
            extra_create={"size": int(d.get("Size") or 0)},
        )
        #self._add_score(guid, eff)

    def _handle_registry(self, event: dict, event_type: str,
                         detection: Optional[dict] = None):
        """Registry events 12/13/14. Stored only when process.score > 0."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid   = d.get("ProcessGuid") or ""
        reg_id = (d.get("TargetObject") or "").lower()
        image  = (d.get("Image")        or "").lower()
        cmd    = d.get("CommandLine")   or ""
        user   = (d.get("User")         or "").lower()
        if not guid or not reg_id:
            return
        eff       = ep["total_score"]
        t_hash=self._upsert_template(image, "", cmd, user, "", ts, eff)
        cur_score = self._get_score(guid)

        #if not (eff+cur_score)> 0:
            
        #    return

        pid = int(d.get("ProcessId") or 0) or None
        self._create_or_promote_instance(
            guid=guid, image=image, parent_image="",
            cmdline=cmd, user=user, description="",
            score=eff, timestamp=ts,t_hash=t_hash,pid=pid
        )
        self._run("MERGE (reg:Registry {id: $id})", {"id": reg_id})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="MODIFIED_REGISTRY",
            dst_id=reg_id, dst_label="Registry",
            ep=ep, eff_score=eff, timestamp=ts,
            extra_create={"event_type": event_type},
        )
        #self._add_score(guid, eff)

    def handle_event_12(self, e, d=None): self._handle_registry(e, "add",    d)
    def handle_event_13(self, e, d=None): self._handle_registry(e, "set",    d)
    def handle_event_14(self, e, d=None): self._handle_registry(e, "rename", d)

    def handle_event_15(self, event: dict, detection: Optional[dict] = None):
        """CreateStreamHash — ADS. ALWAYS_STORE."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid    = d.get("ProcessGuid") or ""
        file_id = (d.get("TargetFilename") or "").lower()
        image   = (d.get("Image")          or "").lower()
        cmd     = d.get("CommandLine")     or ""
        user    = (d.get("User")           or "").lower()
        if not guid or not file_id:
            return

        eff = ep["total_score"]
        cur_score = self._get_score(guid)
        t_hash = self._upsert_template(image, "", cmd, user, "", ts, eff)
        # Gate check FIRST
        #if not (eff+cur_score)> 0:
        #    return

        pid = int(d.get("ProcessId") or 0) or None
        self._create_or_promote_instance(
            guid=guid, image=image, parent_image="",
            cmdline=cmd, user=user, description="",
            score=eff, timestamp=ts, t_hash=t_hash,pid=pid
        )
       # TO
        sha256 = (d.get("Hashes") or "").split("SHA256=")[-1].split(",")[0].lower() if "SHA256=" in (d.get("Hashes") or "") else ""
        self._run("""
    MERGE (f:File {id: $id})
    ON CREATE SET f.sha256 = $sha256
    ON MATCH SET  f.sha256 = $sha256
""", {"id": file_id, "sha256": sha256})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="WROTE_ADS",
            dst_id=file_id, dst_label="File",
            ep=ep, eff_score=eff, timestamp=ts,
            extra_create={"stream_name": d.get("StreamName") or ""},
        )

    def handle_event_22(self, event: dict, detection: Optional[dict] = None):
        """DNSQuery. Stored only when process.score > 0."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid  = d.get("ProcessGuid") or ""
        query = (d.get("QueryName")  or "").lower()
        image = (d.get("Image")      or "").lower()
        cmd   = d.get("CommandLine") or ""
        user  = (d.get("User")       or "").lower()
        if not guid or not query:
            return
        
        eff       = ep["total_score"]
        t_hash=self._upsert_template(image, "", cmd, user, "", ts, eff)
        cur_score = self._get_score(guid)

        #if not (eff+cur_score)> 0:
        #    return
        pid = int(d.get("ProcessId") or 0) or None
        
        self._create_or_promote_instance(
            guid=guid, image=image, parent_image="",
            cmdline=cmd, user=user, description="",
            score=eff, timestamp=ts,t_hash=t_hash,pid=pid
        )
        self._run("MERGE (dns:DNS {id: $q})", {"q": query})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="QUERIED_DNS",
            dst_id=query, dst_label="DNS",
            ep=ep, eff_score=eff, timestamp=ts,
        )
        #self._add_score(guid, eff)

    def handle_event_23(self, event: dict, detection: Optional[dict] = None):
        """FileDelete. Stored only when process.score > 0."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid    = d.get("ProcessGuid") or ""
        file_id = (d.get("TargetFilename") or "").lower()
        image   = (d.get("Image")          or "").lower()
        cmd     = d.get("CommandLine")     or ""
        user    = (d.get("User")           or "").lower()
        if not guid or not file_id:
            return

        eff       = ep["total_score"]
        cur_score = self._get_score(guid)
        t_hash=self._upsert_template(image, "", cmd, user, "", ts, eff)
        #if not (eff+cur_score)> 0:
           
        #    return

        pid = int(d.get("ProcessId") or 0) or None
        self._create_or_promote_instance(
            guid=guid, image=image, parent_image="",
            cmdline=cmd, user=user, description="",
            score=eff, timestamp=ts,t_hash=t_hash,pid=pid
        )
        sha256 = (d.get("Hashes") or "").split("SHA256=")[-1].split(",")[0].lower() if "SHA256=" in (d.get("Hashes") or "") else ""
        self._run("""
            MERGE (f:File {id: $id})
            ON CREATE SET f.sha256 = $sha256
            ON MATCH SET  f.sha256 = $sha256
        """, {"id": file_id, "sha256": sha256})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="DELETED",
            dst_id=file_id, dst_label="File",
            ep=ep, eff_score=eff, timestamp=ts,
        )
        #self._add_score(guid, eff)

    def handle_event_25(self, event: dict, detection: Optional[dict] = None):
       """
       ProcessTampering. ALWAYS_STORE.
       Both attacker and victim scored independently.
       NO CHILD_OF. NO inheritance.
       """
       d  = event.get("data", event)
       ep = self._edge_params(detection)
       ts = d.get("UtcTime") or self._now()

       atk_guid  = d.get("ProcessGuid")       or ""
       vic_guid  = d.get("TargetProcessGuid")  or d.get("TargetProcessGUID")or ""
       atk_image = (d.get("Image")        or "").lower()
       vic_image = (d.get("TargetImage")  or "").lower()
       atk_user  = (d.get("User")         or "").lower()
       vic_user  = (d.get("TargetUser")   or "").lower()
       if not atk_guid or not vic_guid:
           return

       eff = ep["total_score"]
       atk_cur_score = self._get_score(atk_guid)
       vic_cur_score = self._get_score(vic_guid)
       atk_t_hash = self._upsert_template(atk_image, "", "", atk_user, "", ts, eff )
       # Attacker - with gate check
       atk_should_store =(eff+atk_cur_score)> 0 or (eff+vic_cur_score)> 0
       vic_t_hash = self._upsert_template(vic_image, "", "", vic_user, "", ts, eff )
       #if atk_should_store:
       src_pid = int(d.get("SourceProcessId") or 0) or None
       tgt_pid = int(d.get("TargetProcessId") or 0)   or None
       self._create_or_promote_instance(
               guid=atk_guid, image=atk_image, parent_image="",
               cmdline="", user=atk_user, description="",
               score=eff, timestamp=ts, t_hash=atk_t_hash,pid=src_pid
           )
     
       # Victim - with gate check
           
        
       self._create_or_promote_instance(
                    guid=vic_guid, image=vic_image, parent_image="",
                    cmdline="", user=vic_user, description="",
                    score=eff, timestamp=ts, t_hash=vic_t_hash,pid=tgt_pid
                )

       # Edge only if BOTH instances exist
       if self._instance_exists(atk_guid) and self._instance_exists(vic_guid):
            self._merge_edge(
                   src_id=atk_guid, src_label="ProcessInstance",
                   rel_type="TAMPERED",
                   dst_id=vic_guid, dst_label="ProcessInstance",
                   ep=ep, eff_score=eff, timestamp=ts,
                   extra_create={"type": d.get("Type") or ""},
               )
    def handle_event_5(self, event: dict, detection: Optional[dict] = None):
        """ProcessTerminate — mark instance dead."""
        d    = event.get("data", event)
        guid = d.get("ProcessGuid") or ""
        ts   = d.get("UtcTime")     or self._now()
        if guid:
            self._run(
                """
                MATCH (p:ProcessInstance {id: $guid})
                SET p.alive = false, p.end_time = $ts
                """,
                {"guid": guid, "ts": ts},
            )

    # ─────────────────────────────────────────
    # LLM TOOL
    # ─────────────────────────────────────────

    def check_chain_gaps(self, guid: str) -> dict:
        """
        LLM tool. Given a ProcessInstance GUID, returns parent chain info
        and flags any ghost parents (parents that never triggered a detection).
        """
        rows = self._fetch(
            """
            MATCH (p:ProcessInstance {id: $guid})
            OPTIONAL MATCH (p)-[:CHILD_OF]->(parent:ProcessInstance)
            OPTIONAL MATCH (p)-[:INSTANCE_OF]->(t:ProcessTemplate)
            RETURN
                p.id         AS id,
                p.score      AS score,
                p.ghost      AS ghost,
                t.image      AS image,
                t.user       AS user,
                parent.id    AS parent_id,
                parent.score AS parent_score,
                parent.ghost AS parent_ghost
            """,
            {"guid": guid},
        )
        if not rows:
            return {"error": f"ProcessInstance {guid} not found"}

        r    = rows[0]
        gaps = []

        if r.get("parent_ghost"):
            gaps.append({
                "type":        "ghost_parent",
                "parent_id":   r["parent_id"],
                "message": (
                    f"Parent (guid={r['parent_id']}) is a ghost — "
                    f"it has never triggered a detection. "
                    f"Chain is structurally complete but parent "
                    f"has no behavioral data. Check child template's "
                    f"parent_image field to identify the binary."
                ),
            })
        elif not r.get("parent_id"):
            gaps.append({
                "type":    "no_parent",
                "message": "No parent — process predates monitoring or is a root process.",
            })

        return {
            "guid":         r["id"],
            "image":        r.get("image"),
            "user":         r.get("user"),
            "score":        r["score"],
            "ghost":        r["ghost"],
            "parent_id":    r.get("parent_id"),
            "parent_score": r.get("parent_score"),
            "parent_ghost": r.get("parent_ghost"),
            "gaps":         gaps,
        }

    # ─────────────────────────────────────────
    # DISPATCHER
    # ─────────────────────────────────────────

    _HANDLERS = {
        1:  "handle_event_1",   2:  "handle_event_2",
        3:  "handle_event_3",   5:  "handle_event_5",
        6:  "handle_event_6",   7:  "handle_event_7",
        8:  "handle_event_8",   10: "handle_event_10",
        11: "handle_event_11",  12: "handle_event_12",
        13: "handle_event_13",  14: "handle_event_14",
        15: "handle_event_15",  22: "handle_event_22",
        23: "handle_event_23",  25: "handle_event_25",
    }

    def process_event(self, event: dict, detection: Optional[dict] = None):
        try:
            event_id = int(event.get("event_id", -1))
            handler  = self._HANDLERS.get(event_id)
            if handler:
                getattr(self, handler)(event, detection)
            else:
                print(f"[GRAPH] No handler for event_id={event_id}")
        except Exception:
            traceback.print_exc()