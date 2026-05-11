"""
pat_builder.py  —  Process Artifact Tree (PAT)
================================================

The PAT is a complete, append-only, per-process forensic ledger stored in Redis.
It runs in PARALLEL with the graph builder, updated on EVERY event unconditionally.

Unlike the threat graph (sparse, scored, pruned), the PAT:
  - Stores ALL events for ALL processes — no sigma gate
  - Is NEVER pruned by score
  - Has its own TTL (default 7 days), independent of Memgraph pruning
  - Is the ground truth consumed by the Remediation Agent

Redis Key Layout
────────────────
  pat:identity:{guid}      → Hash    static process metadata + trust signals
  pat:actions:{guid}       → Stream  ordered append-only action log
  pat:host_index:{host_id} → Set     all GUIDs seen on a host
  pat:children:{guid}      → Set     direct child GUIDs  (downward walk)
  pat:file_index:{path}    → Set     GUIDs that touched this file path
  pat:ip_index:{ip}        → Set     GUIDs that connected to this IP
  pat:dns_index:{domain}   → Set     GUIDs that queried this domain

Trust / Integrity fields stored in identity hash (for pivot-point detection)
─────────────────────────────────────────────────────────────────────────────
  integrity_level : System | High | Medium | Low | Untrusted  (Sysmon IntegrityLevel)
  signature       : signer / company name, empty if unsigned
  signed          : "true" | "false" | ""
  image_path      : full original-case exe path — used to detect suspicious locations
                    e.g. \\AppData\\Local\\Temp, \\Users\\Public, C:\\Windows\\Temp
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import redis

# ── Redis config ──────────────────────────────────────────────────────────────
REDIS_HOST = "localhost"
REDIS_PORT  = 6379
REDIS_DB    = 0

PAT_TTL_SECONDS    = 7 * 24 * 3600   # 7 days — independent of graph pruning
PAT_ACTIONS_MAXLEN = 2000             # max stream entries per process

_PFX_IDENTITY = "pat:identity:"
_PFX_ACTIONS  = "pat:actions:"
_PFX_HOST_IDX = "pat:host_index:"
_PFX_CHILDREN = "pat:children:"
_PFX_FILE_IDX = "pat:file_index:"
_PFX_IP_IDX   = "pat:ip_index:"
_PFX_DNS_IDX  = "pat:dns_index:"


# ══════════════════════════════════════════════════════════════════════════════
class PATBuilder:
    """
    Process Artifact Tree builder.
    One singleton instance lives for the lifetime of the agent process.
    Call process_event() on every incoming sysmon event before the sigma gate.
    """

    def __init__(self, host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB):
        self.r = redis.Redis(host=host, port=port, db=db, decode_responses=True)
        self.r.ping()
        print("[PAT] Connected to Redis — Process Artifact Tree ready.")

    # ──────────────────────────────────────────────────────────────────────────
    # KEY HELPERS
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _identity_key(self, guid): return f"{_PFX_IDENTITY}{guid}"
    def _actions_key(self, guid):  return f"{_PFX_ACTIONS}{guid}"
    def _host_key(self, host):     return f"{_PFX_HOST_IDX}{host}"
    def _children_key(self, guid): return f"{_PFX_CHILDREN}{guid}"
    def _file_key(self, path):     return f"{_PFX_FILE_IDX}{path[:200]}"
    def _ip_key(self, ip):         return f"{_PFX_IP_IDX}{ip}"
    def _dns_key(self, domain):    return f"{_PFX_DNS_IDX}{domain}"

    def _ttl(self, *keys):
        for k in keys:
            if k:
                self.r.expire(k, PAT_TTL_SECONDS)

    def _refresh_ttl(self, guid: str):
        self._ttl(self._identity_key(guid), self._actions_key(guid))

    # ──────────────────────────────────────────────────────────────────────────
    # IDENTITY WRITE
    # ──────────────────────────────────────────────────────────────────────────

    def _set_identity(
        self, *,
        guid, image, image_path,
        parent_guid, parent_image,
        cmdline, user, pid, host_id, start_time,
        integrity_level, signature, signed,
    ):
        """
        Write process identity into Redis Hash.
        HSETNX for all static fields — first write wins, never overwritten.

        Trust fields (integrity_level, signature, signed, image_path) are critical
        for the remediation agent's pivot-point detection:
          - signed=false + image_path in suspicious dir  → high suspicion
          - integrity_level=High + signed=true + known MS binary → likely legitimate
        """
        key  = self._identity_key(guid)
        pipe = self.r.pipeline()

        static_fields = {
            "guid":            guid,
            "image":           image,
            "image_path":      image_path,
            "parent_guid":     parent_guid,
            "parent_image":    parent_image,
            "cmdline":         cmdline,
            "user":            user,
            "pid":             str(pid) if pid else "",
            "host_id":         host_id,
            "start_time":      start_time,
            # Trust signals
            "integrity_level": integrity_level,
            "signature":       signature,
            "signed":          signed,
        }
        for field, value in static_fields.items():
            pipe.hsetnx(key, field, value or "")

        # Mutable fields — always refreshed on every event
        pipe.hset(key, "alive",    "true")
        pipe.hset(key, "end_time", "")
        pipe.expire(key, PAT_TTL_SECONDS)
        pipe.execute()

        # Host index — "all GUIDs seen on host X"
        if host_id:
            self.r.sadd(self._host_key(host_id), guid)
            self._ttl(self._host_key(host_id))

        # Children index — enables downward BFS from any ancestor
        if parent_guid:
            self.r.sadd(self._children_key(parent_guid), guid)
            self._ttl(self._children_key(parent_guid))

    # ──────────────────────────────────────────────────────────────────────────
    # ACTION APPEND  +  REVERSE ARTIFACT INDEXES
    # ──────────────────────────────────────────────────────────────────────────

    def _append_action(self, guid: str, action_type: str, ts: str, **fields):
        """
        Append one action to the process stream.
        Simultaneously maintains reverse indexes for O(1) artifact→guid lookup.
        """
        key   = self._actions_key(guid)
        entry = {"type": action_type, "ts": ts or self._now()}
        for k, v in fields.items():
            if v is not None and v != "":
                entry[k] = str(v)

        self.r.xadd(key, entry, maxlen=PAT_ACTIONS_MAXLEN, approximate=True)
        self._ttl(key)

        # file path → guid
        if action_type in ("file_created", "file_modified", "file_deleted",
                           "file_timestomped", "wrote_ads"):
            if p := fields.get("path", ""):
                self.r.sadd(self._file_key(p), guid)
                self._ttl(self._file_key(p))

        # ip → guid
        if action_type == "network_connection":
            if ip := fields.get("dst_ip", ""):
                self.r.sadd(self._ip_key(ip), guid)
                self._ttl(self._ip_key(ip))

        # domain → guid
        if action_type == "dns_query":
            if d := fields.get("query", ""):
                self.r.sadd(self._dns_key(d), guid)
                self._ttl(self._dns_key(d))

    # ──────────────────────────────────────────────────────────────────────────
    # PUBLIC: MAIN EVENT ENTRY POINT
    # ──────────────────────────────────────────────────────────────────────────

    def process_event(self, event: dict) -> None:
        """
        Called on EVERY sysmon event — no sigma gate, no score gate.
        Routes to the appropriate handler by event_id.
        """
        try:
            event_id = int(event.get("event_id", -1))
            handler  = self._HANDLERS.get(event_id)
            if handler:
                getattr(self, handler)(event)
        except Exception as e:
            print(f"[PAT][ERROR] event_id={event.get('event_id')} → {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # EVENT HANDLERS
    # ──────────────────────────────────────────────────────────────────────────

    def _handle_event_1(self, event: dict):
        """
        ProcessCreate — THE most important event.
        Only Event 1 writes parent_guid, parent_image, integrity_level,
        signature, signed. All other events call _ensure_identity which
        is a no-op if Event 1 already ran for this GUID.
        """
        d    = event.get("data", event)
        ts   = d.get("UtcTime")           or self._now()
        host = d.get("Computer")          or event.get("host_id", "")

        # Child (new process)
        child_guid  = d.get("ProcessGuid")         or ""
        child_image = (d.get("Image")              or "").lower()
        child_path  = d.get("Image")               or ""   # original case for path analysis
        child_cmd   = d.get("CommandLine")         or ""
        child_user  = (d.get("User")               or "").lower()
        child_pid   = int(d.get("ProcessId")       or 0) or None
        child_il    = d.get("IntegrityLevel")      or ""
        # Sysmon Event 1 exposes Company as a trust proxy when Signed is absent
        child_sig   = d.get("Company") or d.get("Signature") or ""
        child_signed= d.get("Signed")              or ""

        # Parent
        par_guid    = d.get("ParentProcessGuid")   or ""
        par_image   = (d.get("ParentImage")        or "").lower()
        par_path    = d.get("ParentImage")          or ""
        par_cmd     = d.get("ParentCommandLine")   or ""
        par_user    = (d.get("ParentUser")         or "").lower()
        par_pid     = int(d.get("ParentProcessId") or 0) or None

        # Write parent identity (HSETNX — no-op if already written by earlier spawn)
        if par_guid:
            self._set_identity(
                guid=par_guid,        image=par_image,  image_path=par_path,
                parent_guid="",       parent_image="",
                cmdline=par_cmd,      user=par_user,    pid=par_pid,
                host_id=host,         start_time=ts,
                integrity_level="",   signature="",     signed="",
            )
            self._append_action(par_guid, "child_spawned", ts,
                                child_guid=child_guid,
                                child_image=child_image,
                                child_cmdline=child_cmd)

        # Write child identity — parent_guid here enables ancestry walk
        if child_guid:
            self._set_identity(
                guid=child_guid,          image=child_image,  image_path=child_path,
                parent_guid=par_guid,     parent_image=par_image,
                cmdline=child_cmd,        user=child_user,    pid=child_pid,
                host_id=host,             start_time=ts,
                integrity_level=child_il, signature=child_sig, signed=child_signed,
            )

    def _handle_event_2(self, event: dict):
        """FileCreateTime — timestomp."""
        d = event.get("data", event)
        ts = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid: return
        self._ensure_identity(event)
        self._append_action(guid, "file_timestomped", ts,
                            path=  (d.get("TargetFilename") or "").lower(),
                            sha256=self._sha256(d.get("Hashes", "")))
        self._refresh_ttl(guid)

    def _handle_event_3(self, event: dict):
        """NetworkConnect."""
        d = event.get("data", event)
        ts = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid: return
        self._ensure_identity(event)
        self._append_action(guid, "network_connection", ts,
                            dst_ip=   (d.get("DestinationIp")       or "").lower(),
                            dst_port= d.get("DestinationPort")       or "",
                            src_ip=   (d.get("SourceIp")            or "").lower(),
                            src_port= d.get("SourcePort")            or "",
                            protocol= (d.get("Protocol")            or "").lower(),
                            dst_host= (d.get("DestinationHostname") or "").lower(),
                            initiated=d.get("Initiated")             or "")
        self._refresh_ttl(guid)

    def _handle_event_5(self, event: dict):
        """ProcessTerminate — mark process as dead in identity hash."""
        d = event.get("data", event)
        ts = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid: return
        key = self._identity_key(guid)
        if self.r.exists(key):
            self.r.hset(key, mapping={"alive": "false", "end_time": ts})
            self._refresh_ttl(guid)

    def _handle_event_6(self, event: dict):
        """DriverLoad."""
        d = event.get("data", event)
        ts = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid: return
        self._ensure_identity(event)
        self._append_action(guid, "driver_loaded", ts,
                            sha256=      self._sha256(d.get("Hashes", "")),
                            image_loaded=(d.get("ImageLoaded") or "").lower(),
                            signed=      d.get("Signed")       or "",
                            signature=   d.get("Signature")    or "")
        self._refresh_ttl(guid)

    def _handle_event_7(self, event: dict):
        """ImageLoad — DLL loaded."""
        d = event.get("data", event)
        ts = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid: return
        self._ensure_identity(event)
        self._append_action(guid, "image_loaded", ts,
                            image_loaded=(d.get("ImageLoaded") or "").lower(),
                            sha256=      self._sha256(d.get("Hashes", "")),
                            signed=      d.get("Signed")       or "",
                            signature=   d.get("Signature")    or "")
        self._refresh_ttl(guid)

    def _handle_event_8(self, event: dict):
        """CreateRemoteThread — thread injection, both sides."""
        d   = event.get("data", event)
        ts  = d.get("UtcTime") or self._now()
        src = d.get("SourceProcessGuid") or ""
        tgt = d.get("TargetProcessGuid") or d.get("TargetProcessGUID") or ""

        if src:
            self._ensure_identity(event, guid_field="SourceProcessGuid",
                                  image_field="SourceImage", user_field="SourceUser",
                                  pid_field="SourceProcessId")
            self._append_action(src, "injected_thread_into", ts,
                                target_guid=   tgt,
                                target_image=  (d.get("TargetImage")   or "").lower(),
                                start_address= d.get("StartAddress")   or "",
                                start_module=  (d.get("StartModule")   or "").lower(),
                                start_function=d.get("StartFunction")  or "")
            self._refresh_ttl(src)

        if tgt:
            self._ensure_identity(event, guid_field="TargetProcessGuid",
                                  image_field="TargetImage", user_field="TargetUser",
                                  pid_field="TargetProcessId")
            self._append_action(tgt, "received_injected_thread", ts,
                                source_guid=   src,
                                source_image=  (d.get("SourceImage")  or "").lower(),
                                start_address= d.get("StartAddress")  or "",
                                start_function=d.get("StartFunction") or "")
            self._refresh_ttl(tgt)

    def _handle_event_10(self, event: dict):
        """ProcessAccess — memory read/write."""
        d   = event.get("data", event)
        ts  = d.get("UtcTime") or self._now()
        src = d.get("SourceProcessGuid") or d.get("SourceProcessGUID") or ""
        tgt = d.get("TargetProcessGuid") or d.get("TargetProcessGUID") or ""

        if src:
            self._ensure_identity(event, guid_field="SourceProcessGuid",
                                  image_field="SourceImage", user_field="SourceUser",
                                  pid_field="SourceProcessId")
            self._append_action(src, "accessed_process_memory", ts,
                                target_guid= tgt,
                                target_image=(d.get("TargetImage")  or "").lower(),
                                access_mask= d.get("GrantedAccess") or "")
            self._refresh_ttl(src)

        if tgt:
            self._ensure_identity(event, guid_field="TargetProcessGuid",
                                  image_field="TargetImage", user_field="TargetUser",
                                  pid_field="TargetProcessId")
            self._append_action(tgt, "memory_was_accessed_by", ts,
                                source_guid= src,
                                source_image=(d.get("SourceImage") or "").lower(),
                                access_mask= d.get("GrantedAccess") or "")
            self._refresh_ttl(tgt)

    def _handle_event_11(self, event: dict):
        """FileCreate."""
        d = event.get("data", event)
        ts = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid: return
        self._ensure_identity(event)
        self._append_action(guid, "file_created", ts,
                            path=  (d.get("TargetFilename") or "").lower(),
                            sha256=self._sha256(d.get("Hashes", "")))
        self._refresh_ttl(guid)

    def _handle_registry(self, event: dict, reg_type: str):
        d = event.get("data", event)
        ts = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid: return
        self._ensure_identity(event)
        self._append_action(guid, "registry_write", ts,
                            reg_type= reg_type,
                            key=      (d.get("TargetObject") or "").lower(),
                            details=  d.get("Details")       or "",
                            new_name= (d.get("NewName")      or "").lower())
        self._refresh_ttl(guid)

    def _handle_event_12(self, e): self._handle_registry(e, "add")
    def _handle_event_13(self, e): self._handle_registry(e, "set")
    def _handle_event_14(self, e): self._handle_registry(e, "rename")

    def _handle_event_15(self, event: dict):
        """Alternate Data Stream."""
        d = event.get("data", event)
        ts = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid: return
        self._ensure_identity(event)
        self._append_action(guid, "wrote_ads", ts,
                            path=       (d.get("TargetFilename") or "").lower(),
                            stream_name=d.get("StreamName")      or "",
                            sha256=     self._sha256(d.get("Hashes", "")))
        self._refresh_ttl(guid)

    def _handle_event_22(self, event: dict):
        """DNSQuery."""
        d = event.get("data", event)
        ts = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid: return
        self._ensure_identity(event)
        self._append_action(guid, "dns_query", ts,
                            query=  (d.get("QueryName")   or "").lower(),
                            results=d.get("QueryResults") or "",
                            status= d.get("QueryStatus")  or "")
        self._refresh_ttl(guid)

    def _handle_event_23(self, event: dict):
        """FileDelete."""
        d = event.get("data", event)
        ts = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid: return
        self._ensure_identity(event)
        self._append_action(guid, "file_deleted", ts,
                            path=    (d.get("TargetFilename") or "").lower(),
                            sha256=  self._sha256(d.get("Hashes", "")),
                            archived=d.get("IsExecutable")    or "")
        self._refresh_ttl(guid)

    def _handle_event_25(self, event: dict):
        """ProcessTampering — hollowing / herpadering."""
        d   = event.get("data", event)
        ts  = d.get("UtcTime") or self._now()
        atk = d.get("ProcessGuid")       or ""
        vic = d.get("TargetProcessGuid") or d.get("TargetProcessGUID") or ""

        if atk:
            self._ensure_identity(event)
            self._append_action(atk, "tampered_process", ts,
                                target_guid= vic,
                                target_image=(d.get("TargetImage") or "").lower(),
                                tamper_type= d.get("Type")         or "")
            self._refresh_ttl(atk)

        if vic:
            self._ensure_identity(event, guid_field="TargetProcessGuid",
                                  image_field="TargetImage", user_field="TargetUser",
                                  pid_field="TargetProcessId")
            self._append_action(vic, "was_tampered_by", ts,
                                source_guid= atk,
                                source_image=(d.get("Image") or "").lower(),
                                tamper_type= d.get("Type")   or "")
            self._refresh_ttl(vic)

    _HANDLERS = {
        1:  "_handle_event_1",   2:  "_handle_event_2",
        3:  "_handle_event_3",   5:  "_handle_event_5",
        6:  "_handle_event_6",   7:  "_handle_event_7",
        8:  "_handle_event_8",   10: "_handle_event_10",
        11: "_handle_event_11",  12: "_handle_event_12",
        13: "_handle_event_13",  14: "_handle_event_14",
        15: "_handle_event_15",  22: "_handle_event_22",
        23: "_handle_event_23",  25: "_handle_event_25",
    }

    # ──────────────────────────────────────────────────────────────────────────
    # INTERNAL UTILITIES
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _sha256(hashes_str: str) -> str:
        if not hashes_str or "SHA256=" not in hashes_str:
            return ""
        return hashes_str.split("SHA256=")[-1].split(",")[0].lower()

    def _ensure_identity(
        self, event: dict,
        guid_field="ProcessGuid", image_field="Image",
        user_field="User",        pid_field="ProcessId",
    ):
        """
        Best-effort identity write for non-Event-1 events.
        HSETNX is idempotent — no-op if Event 1 already populated this GUID.
        Trust fields left empty here; Event 1 fills them in.
        """
        d    = event.get("data", event)
        guid = d.get(guid_field) or ""
        if not guid: return
        self._set_identity(
            guid=guid,
            image=      (d.get(image_field) or "").lower(),
            image_path= d.get(image_field)  or "",
            parent_guid="", parent_image="",
            cmdline="",
            user=       (d.get(user_field)  or "").lower(),
            pid=        int(d.get(pid_field) or 0) or None,
            host_id=    d.get("Computer")   or event.get("host_id", ""),
            start_time= d.get("UtcTime")    or self._now(),
            integrity_level="", signature="", signed="",
        )

    # ──────────────────────────────────────────────────────────────────────────
    # PUBLIC: REMEDIATION CONTEXT  (consumed by RemediationContextBuilder)
    # ──────────────────────────────────────────────────────────────────────────

    def build_remediation_context(
        self,
        flagged_guid: str,
        max_depth: int = 20,
    ) -> dict:
        """
        Returns full forensic context for a flagged GUID:
          ancestry_chain   : root → flagged node (upward walk)
                             each node includes trust signals for pivot-point detection
          blast_radius     : flagged node + all descendants (downward BFS)
                             these are the kill candidates
          injection_victims: cross-process targets from blast radius action logs
                             these need scanning, not killing
          chain_truncated  : True if ancestry walk hit a missing PAT key
                             (process predated monitoring or TTL expired)
        """
        # ── Upward walk ───────────────────────────────────────────────────────
        ancestry_guids  = []
        current         = flagged_guid
        seen            = set()
        chain_truncated = False

        for _ in range(max_depth):
            if not current or current in seen:
                break
            seen.add(current)
            ancestry_guids.append(current)
            identity = self.r.hgetall(self._identity_key(current))
            if not identity:
                chain_truncated = True
                break
            parent = identity.get("parent_guid", "")
            if not parent:
                break
            current = parent

        ancestry_guids.reverse()  # root first

        # ── Downward BFS from flagged node ────────────────────────────────────
        blast_guids  = []
        queue        = [flagged_guid]
        visited_down = set()

        while queue:
            node = queue.pop(0)
            if node in visited_down:
                continue
            visited_down.add(node)
            blast_guids.append(node)
            for child in self.r.smembers(self._children_key(node)):
                if child not in visited_down:
                    queue.append(child)

        # ── Injection victims from blast radius ───────────────────────────────
        injection_victims = []
        seen_victims      = set()
        for guid in blast_guids:
            for action in self.get_actions_by_type(guid, "injected_thread_into"):
                tgt = action.get("target_guid", "")
                if tgt and tgt not in seen_victims and tgt not in visited_down:
                    seen_victims.add(tgt)
                    tgt_id = self.r.hgetall(self._identity_key(tgt))
                    injection_victims.append({
                        "guid":            tgt,
                        "image":           tgt_id.get("image",           "unknown") if tgt_id else "unknown",
                        "image_path":      tgt_id.get("image_path",      "")        if tgt_id else "",
                        "injected_by":     guid,
                        "signed":          tgt_id.get("signed",          "")        if tgt_id else "",
                        "signature":       tgt_id.get("signature",       "")        if tgt_id else "",
                        "integrity_level": tgt_id.get("integrity_level", "")        if tgt_id else "",
                    })

        # ── Build full node record (identity + all raw actions) ───────────────
        def _node(guid: str) -> dict:
            ident = self.r.hgetall(self._identity_key(guid))
            acts  = [f for _, f in self.r.xrange(self._actions_key(guid))]
            base  = {
                "guid": guid, "image": "", "image_path": "",
                "parent_guid": "", "parent_image": "",
                "cmdline": "", "user": "", "pid": "",
                "host_id": "", "start_time": "", "end_time": "",
                "alive": None,
                "integrity_level": "", "signature": "", "signed": "",
                "actions": acts,
            }
            if ident:
                base.update({
                    "guid":            ident.get("guid",            guid),
                    "image":           ident.get("image",           ""),
                    "image_path":      ident.get("image_path",      ""),
                    "parent_guid":     ident.get("parent_guid",     ""),
                    "parent_image":    ident.get("parent_image",    ""),
                    "cmdline":         ident.get("cmdline",         ""),
                    "user":            ident.get("user",            ""),
                    "pid":             ident.get("pid",             ""),
                    "host_id":         ident.get("host_id",         ""),
                    "start_time":      ident.get("start_time",      ""),
                    "end_time":        ident.get("end_time",        ""),
                    "alive":           ident.get("alive", "true") == "true",
                    "integrity_level": ident.get("integrity_level", ""),
                    "signature":       ident.get("signature",       ""),
                    "signed":          ident.get("signed",          ""),
                })
            return base

        ancestry_chain = [_node(g) for g in ancestry_guids if g not in visited_down]
        blast_radius   = [_node(g) for g in blast_guids]

        return {
            "flagged_guid":      flagged_guid,
            "chain_truncated":   chain_truncated,
            "ancestry_chain":    ancestry_chain,
            "blast_radius":      blast_radius,
            "injection_victims": injection_victims,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # PUBLIC: REVERSE INDEX LOOKUPS
    # ──────────────────────────────────────────────────────────────────────────

    def find_guids_by_file(self, path: str)    -> list[str]:
        return list(self.r.smembers(self._file_key(path.lower())))

    def find_guids_by_ip(self, ip: str)        -> list[str]:
        return list(self.r.smembers(self._ip_key(ip.lower())))

    def find_guids_by_domain(self, domain: str) -> list[str]:
        return list(self.r.smembers(self._dns_key(domain.lower())))

    # ──────────────────────────────────────────────────────────────────────────
    # PUBLIC: GENERAL LOOKUPS
    # ──────────────────────────────────────────────────────────────────────────

    def get_identity(self, guid: str) -> Optional[dict]:
        r = self.r.hgetall(self._identity_key(guid))
        return r if r else None

    def get_actions(self, guid: str) -> list[dict]:
        return [f for _, f in self.r.xrange(self._actions_key(guid))]

    def get_actions_by_type(self, guid: str, action_type: str) -> list[dict]:
        return [a for a in self.get_actions(guid) if a.get("type") == action_type]

    def get_guids_on_host(self, host_id: str) -> list[str]:
        return list(self.r.smembers(self._host_key(host_id)))

    def get_children(self, guid: str) -> list[str]:
        return list(self.r.smembers(self._children_key(guid)))

    def get_parent_chain(self, guid: str, max_depth: int = 20) -> list[str]:
        """Return ordered list of GUIDs from root → given GUID."""
        chain, current, seen = [], guid, set()
        for _ in range(max_depth):
            if not current or current in seen: break
            seen.add(current)
            chain.append(current)
            ident  = self.r.hgetall(self._identity_key(current))
            parent = ident.get("parent_guid", "") if ident else ""
            if not parent: break
            current = parent
        chain.reverse()
        return chain