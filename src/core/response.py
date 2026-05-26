"""
EDR AI Agent Response Functions (with Windows System Protection)
Supports two modes for every action:
  - automatic : executes immediately (for high-confidence, time-critical automation)
  - approval  : prints a structured request and waits for operator confirmation

Every function returns a dict with keys:
  status   : "executed" | "pending_approval" | "approved" | "rejected" | "error" | "blocked"
  action   : name of the action
  target   : the identifier passed in
  details  : free-form information
  timestamp: UTC ISO-8601

Response functions:
    alert
    host_isolation
    shutdown
    blacklist
    process_termination
    file_quarantine
    file_deletion
    patching
    identity_revocation
    registry_delete
    ip_block
    dns_block

"""
import datetime
import getpass
import hashlib
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import winreg
from pathlib import Path
from typing import Any, Dict, Literal, Optional
_approval_callback = None  # module-level
# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [EDR] %(levelname)s %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger("edr")

Mode = Literal["automatic", "approval"]

# ── Protected Resources ───────────────────────────────────────────────────────

class WindowsProtection:
    """Manages protection of critical Windows system resources"""
    
    def __init__(self, config_path: Optional[str] = None):
        base_dir = Path(__file__).resolve().parent
    
        if config_path:
            self.config_path = Path(config_path)
        else:
            self.config_path = base_dir / ".." / ".." / "data" / "windows_protected_resources.json"
    
        self.config_path = self.config_path.resolve()
        self.config = self._load_config()

        
    def _load_config(self) -> Dict:
        """Load protected resources configuration"""
        try:
            config_file = Path(self.config_path)
            if config_file.exists():
                return json.loads(config_file.read_text())
            else:
                log.warning(f"Protected resources config not found at {self.config_path}")
                return self._default_config()
        except Exception as e:
            log.error(f"Failed to load protection config: {e}")
            return self._default_config()
    
    def _default_config(self) -> Dict:
        """Minimal fallback protection config"""
        return {
            "protected_processes": {
                "critical_system": ["csrss.exe", "wininit.exe", "winlogon.exe", 
                                   "services.exe", "lsass.exe", "smss.exe", "system"]
            },
            "protected_directories": ["C:\\Windows\\System32", "C:\\Windows\\SysWOW64"],
            "protected_files": {"kernel": [], "critical_dlls": [], "registry_hives": []},
            "min_protected_pids": {"threshold": 1000},
            "warnings": {
                "process_termination": "CRITICAL: Protected system process",
                "file_quarantine": "CRITICAL: Protected system file",
                "file_deletion": "CRITICAL: Protected system file",
                "general": "CRITICAL: Protected system resource"
            }
        }
    
    def is_protected_process(self, pid: Optional[int] = None, 
                            name: Optional[str] = None) -> tuple[bool, str]:
        """
        Check if a process is protected
        Returns: (is_protected, reason)
        """
        # Check by PID threshold
        if pid is not None:
            threshold = self.config.get("min_protected_pids", {}).get("threshold", 1000)
            if pid < threshold:
                return (True, f"PID {pid} is below protected threshold ({threshold})")
        
        # Check by process name
        if name is not None:
            name_lower = name.lower()
            for category, processes in self.config.get("protected_processes", {}).items():
                protected_names = [p.lower() for p in processes]
                if name_lower in protected_names:
                    return (True, f"Process '{name}' is in protected category: {category}")
        
        return (False, "")
    
    def is_protected_file(self, file_path: str) -> tuple[bool, str]:
        """
        Check if a file is protected
        Returns: (is_protected, reason)
        """
        path = Path(file_path).resolve()
        path_str = str(path)
        path_lower = path_str.lower()
        
        # Check protected directories
        for protected_dir in self.config.get("protected_directories", []):
            if path_lower.startswith(protected_dir.lower()):
                return (True, f"File is in protected directory: {protected_dir}")
        
        # Check exact file matches
        for category, files in self.config.get("protected_files", {}).items():
            for protected_file in files:
                if path_lower == protected_file.lower():
                    return (True, f"File is protected ({category}): {protected_file}")
        
        # Check file patterns
        patterns = self.config.get("protected_file_patterns", [])
        for pattern in patterns:
            if pattern.startswith("*."):
                ext = pattern[1:]  # e.g., ".sys"
                if path_str.lower().endswith(ext):
                    return (True, f"File matches protected pattern: {pattern}")
            elif "*" in pattern:
                # Simple wildcard matching for patterns like "ntoskrnl.*"
                pattern_prefix = pattern.split("*")[0].lower()
                if path.name.lower().startswith(pattern_prefix):
                    return (True, f"File matches protected pattern: {pattern}")
        
        return (False, "")
    
    def get_warning(self, action: str) -> str:
        """Get appropriate warning message for an action"""
        return self.config.get("warnings", {}).get(action, 
                    self.config.get("warnings", {}).get("general", "CRITICAL: Protected resource"))


# Global protection instance
_protection = WindowsProtection()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"


def _result(status: str, action: str, target: str, details: Any = None) -> Dict:
    r = {
        "status": status,
        "action": action,
        "target": target,
        "details": details or {},
        "timestamp": _now(),
    }
    log.info(json.dumps(r))
    return r


def _request_approval(action: str, target: str, details: str) -> bool:
    """
    Blocking approval gate.
    Returns True if the operator approves.
    """
    print("\n" + "=" * 60)
    print(f"  APPROVAL REQUIRED")
    print(f"  Action : {action}")
    print(f"  Target : {target}")
    print(f"  Details: {details}")
    print("=" * 60)
    answer = input("  Type 'yes' to approve, anything else to reject: ").strip().lower()
    return answer == "yes"




def _gate(mode, action, target, description, execute_fn, *args, **kwargs):
    if mode == "automatic":
        try:
            return _result("executed", action, target, execute_fn(*args, **kwargs))
        except Exception as exc:
            return _result("error", action, target, {"error": str(exc)})

    # approval mode — delegate to injected callback
    if _approval_callback is None:
        raise RuntimeError("approval mode requires a callback — call set_approval_callback() first")

    approved = _approval_callback(action, target, description)
    if not approved:
        return _result("rejected", action, target, {"reason": "operator_rejected"})
    try:
        return _result("approved", action, target, execute_fn(*args, **kwargs))
    except Exception as exc:
        return _result("error", action, target, {"error": str(exc)})

def alert(
    identifier: str,
    severity: str,
    message: str,
    mode: Mode = "automatic",
    notify_webhook: Optional[str] = None,
) -> Dict:
    """
    Emit a structured alert. Optionally POST to a webhook.

    Parameters
    ----------
    identifier    : Host GUID, IP, PID, or asset ID associated with the threat.
    severity      : "low" | "medium" | "high" | "critical"
    message       : Human-readable description of the threat.
    notify_webhook: HTTP(S) URL to POST the alert JSON to (optional).
    """
    def _alert():
        payload = {
            "severity": severity,
            "message": message,
            "identifier": identifier,
            "timestamp": _now(),
        }
        log.warning(f"ALERT [{severity.upper()}] {identifier}: {message}")
        if notify_webhook:
            try:
                import requests
                requests.post(notify_webhook, json=payload, timeout=5)
            except Exception as e:
                payload["webhook_error"] = str(e)
        return payload

    return _gate(mode, "alert", identifier,
                 f"[{severity}] {message}", _alert)



def host_isolation(
    mode: Mode = "approval",
) -> Dict:
    """
    Cut a host's network access.
    Implementation notes
    --------------------
    Local (Windows) : netsh / Windows Firewall rules via pywin32 or subprocess.
    """
    def _isolate():
        cmds = [
                ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy",
                 "blockinbound,blockoutbound"],
        ]
        results = []
        for cmd in cmds:
            try:
                subprocess.run(cmd, check=True, capture_output=True)
                results.append({"cmd": " ".join(cmd), "ok": True})
            except subprocess.CalledProcessError as e:
                results.append({"cmd": " ".join(cmd), "ok": False,
                                 "stderr": e.stderr.decode()})
        return {"commands": results}

    return _gate(mode, "host_isolation", "localhost",
                 f"Isolate all network traffic", _isolate)



def shutdown(
    mode: Mode = "approval",
    delay_seconds: int = 30,
    force: bool = False,
) -> Dict:
    """
    Gracefully (or forcefully) shut down the local host.

    Parameters
    ----------
    delay_seconds   : Grace period before shutdown (default 30 s).
    force           : If True, immediate forced shutdown (no grace period).

    """
    def _shutdown():
        cmd = ["shutdown", "/s", "/t", str(delay_seconds)]
        if force:
            cmd.insert(2, "/f")
        subprocess.Popen(cmd)
        return {"command": " ".join(cmd), "delay_seconds": delay_seconds, "force": force}

    desc = f"Shutdown host localhost in {delay_seconds}s (force={force})"
    return _gate(mode, "shutdown", "localhost", desc, _shutdown)



def blacklist(
    identifier: str,
    blacklist_type: Literal["ip", "domain", "hash", "process_name"],
    mode: Mode = "approval",
    blacklist_file: str = "../../config/ioc/agent_blacklist.json",
) -> Dict:
    """
    Add an indicator of compromise to the local blacklist store.

    Parameters
    ----------
    identifier     : IP address, domain, SHA-256 hash, or process name.
    blacklist_type : Category of the indicator.
    blacklist_file : Path to the JSON blacklist database.
    """
    def _blacklist():
        bl_path = Path(blacklist_file)
        bl_path.parent.mkdir(parents=True, exist_ok=True)
        db: dict = {}
        if bl_path.exists():
            db = json.loads(bl_path.read_text())
        db.setdefault(blacklist_type, [])
        if identifier not in db[blacklist_type]:
            db[blacklist_type].append(identifier)
        bl_path.write_text(json.dumps(db, indent=2))
        return {"blacklist_file": str(bl_path), "type": blacklist_type,
                "entry_added": identifier}

    return _gate(mode, "blacklist", identifier,
                 f"Add {blacklist_type} '{identifier}' to blacklist", _blacklist)



def process_termination(
    pid: int,
    mode: Mode = "approval",
    force: bool = True,
) -> Dict:
    """
    Terminate a running process by PID.

    Parameters
    ----------
    pid   : Process ID to kill.
    force : SIGKILL (True) vs SIGTERM (False).
    """
    
    # PROTECTION CHECK: Verify this is not a protected process
    is_protected, reason = _protection.is_protected_process(pid=pid)
    
    if is_protected:
        warning_msg = _protection.get_warning("process_termination")
        log.error(f"{warning_msg} - {reason}")
        print(f"\n{'!' * 60}")
        print(f"  {warning_msg}")
        print(f"  PID: {pid}")
        print(f"  Reason: {reason}")
        print(f"  Action BLOCKED for system safety")
        print(f"{'!' * 60}\n")
        return _result("blocked", "process_termination", str(pid), 
                      {"reason": reason, "warning": warning_msg})
    
    def _terminate():
        try:
            import psutil
            proc = psutil.Process(pid)
            proc_name = proc.name()
            
            # Additional check by process name
            is_protected_name, reason_name = _protection.is_protected_process(name=proc_name)
            if is_protected_name:
                raise PermissionError(f"Protected process: {reason_name}")
            
            info = {"name": proc_name, "exe": proc.exe(), "cmdline": proc.cmdline()}
            if force:
                proc.kill()
            else:
                proc.terminate()
            return {**info, "force": force, "result": "terminated"}
        except ImportError:
            sig = signal.SIGKILL if force else signal.SIGTERM
            os.kill(pid, sig)
            return {"pid": pid, "signal": str(sig), "result": "signal_sent"}

    return _gate(mode, "process_termination", str(pid),
                 f"Terminate PID {pid} (force={force})", _terminate)



def file_quarantine(
    file_path: str,
    mode: Mode = "approval",
    quarantine_dir: str = "../../quarantine",
) -> Dict:
    """
    Move a suspicious file to a locked quarantine directory.
    Quarantined files can be read or deleted but not modified ore executed.

    Parameters
    ----------
    file_path     : Absolute path to the file.
    quarantine_dir: Destination
    """
    
    # PROTECTION CHECK: Verify this is not a protected file
    is_protected, reason = _protection.is_protected_file(file_path)
    
    if is_protected:
        warning_msg = _protection.get_warning("file_quarantine")
        log.error(f"{warning_msg} - {reason}")
        print(f"\n{'!' * 60}")
        print(f"  {warning_msg}")
        print(f"  File: {file_path}")
        print(f"  Reason: {reason}")
        print(f"  Action BLOCKED for system safety")
        print(f"{'!' * 60}\n")
        return _result("blocked", "file_quarantine", file_path, 
                      {"reason": reason, "warning": warning_msg})

    def _quarantine():
        src = Path(file_path)
        if not src.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        q_dir = Path(quarantine_dir)
        q_dir.mkdir(parents=True, exist_ok=True)

        # Calculate hash BEFORE moving
        sha256 = hashlib.sha256(src.read_bytes()).hexdigest()

        dst = q_dir / f"{sha256}_{src.name}"

        # Move the file
        shutil.move(str(src), str(dst))

        # Verify content wasn't lost
        if dst.stat().st_size == 0:
            raise RuntimeError(f"Quarantined file is empty: {dst}")
        commands = [
            # Remove inheritance
            ["icacls", str(dst), "/inheritance:r"],

            # Grant ONLY what you want (read + delete)
            # This implicitly denies everything else (write, modify, execute)
            ["icacls", str(dst), "/grant", "*S-1-1-0:(RX,DC,R,RA)"],

            # Grant current user full control for management
            ["icacls", str(dst), "/grant", f"{os.environ.get('USERNAME')}:(F)"],
        ]

        for cmd in commands:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                # If icacls fails, we still have the file but should log the error
                print(f"Warning: icacls failed: {' '.join(cmd)}\n{result.stderr}")
                # Don't raise - the file is already quarantined

        meta = {
            "original_path": str(src),
            "quarantine_path": str(dst),
            "sha256": sha256,
            "quarantined_at": _now(),
        }
        (q_dir / f"{sha256}.meta.json").write_text(json.dumps(meta, indent=2))
        return meta

    return _gate(mode, "file_quarantine", file_path,
                 f"Quarantine file '{file_path}'", _quarantine)



def file_deletion(
    file_path: str,
    mode: Mode = "approval",
    secure_wipe: bool = True,
    passes: int = 3,
) -> Dict:
    """
    Delete a file, optionally overwriting it before removal (secure wipe).

    Parameters
    ----------
    file_path   : Absolute path to the file.
    secure_wipe : Overwrite with random bytes before deletion.
    passes      : Number of overwrite passes (default 3; DoD 5220.22-M uses 7).
    """
    
    # PROTECTION CHECK: Verify this is not a protected file
    is_protected, reason = _protection.is_protected_file(file_path)
    
    if is_protected:
        warning_msg = _protection.get_warning("file_deletion")
        log.error(f"{warning_msg} - {reason}")
        print(f"\n{'!' * 60}")
        print(f"  {warning_msg}")
        print(f"  File: {file_path}")
        print(f"  Reason: {reason}")
        print(f"  Action BLOCKED for system safety")
        print(f"{'!' * 60}\n")
        return _result("blocked", "file_deletion", file_path, 
                      {"reason": reason, "warning": warning_msg})
    
    def _delete():
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        size = p.stat().st_size
        if secure_wipe and size > 0:
            with p.open("r+b") as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())

        p.unlink()
        return {"deleted": file_path, "secure_wipe": secure_wipe,
                "passes": passes, "size_bytes": size}

    return _gate(mode, "file_deletion", file_path,
                 f"Permanently delete '{file_path}' (wipe={secure_wipe})", _delete)


def patching(
    target: str,
    mode: Mode = "approval",
    package_manager: str = "choco",
    packages: Optional[list] = None,
) -> Dict:
    """
    Apply OS or application patches to remediate a vulnerability.

    Parameters
    ----------
    target         : Hostname / asset GUID (audit trail; runs locally in this stub).
    package_manager: "winget" | "choco" | "pip"
    packages       : Specific packages to update. None = full system upgrade.
    """
    def _patch():
        cmd_map = {
            "pip": ["python", "-m", "pip", "install", "--upgrade"] + (packages or ["pip"]),
            "choco": ["choco", "upgrade","-y"] + (packages if packages else ["all"]),
            "winget": ["winget", "upgrade"] + (packages if packages else ["--all"]),
        }
        cmd = cmd_map.get(package_manager)
        if not cmd:
            raise ValueError(f"Unknown package manager: {package_manager}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        return {"command": " ".join(cmd), "returncode": result.returncode,
                "stdout": result.stdout[-2000:], "stderr": result.stderr[-500:]}

    return _gate(mode, "patching", target,
                 f"Patch {target} via {package_manager} (pkgs: {packages})", _patch)


def dns_block(
        domain: str,
        mode: Mode = "approval",
        hosts_file: str = r"C:\Windows\System32\drivers\etc\hosts",
        redirect_ip: str = "0.0.0.0",
) -> Dict:
    """
    Block a domain by redirecting it to a null IP in the Windows hosts file.
    Blocks both the apex domain and the www subdomain by default.

    Parameters
    ----------
    domain      : The domain to block (e.g. "malicious.com").
    hosts_file  : Path to the hosts file. Defaults to the Windows system hosts file.
    redirect_ip : IP to redirect the domain to. Defaults to 0.0.0.0 (null route).
    """
    # PROTECTION CHECK: Prevent blocking protected system files
    is_protected, reason = _protection.is_protected_file(hosts_file)
    if is_protected:
        warning_msg = _protection.get_warning("file_quarantine")
        log.error(f"{warning_msg} - {reason}")
        return _result("blocked", "dns_block", domain,
                       {"reason": reason, "warning": warning_msg})

    # Build the entries to add: apex + www subdomain
    www_domain = f"www.{domain}" if not domain.startswith("www.") else domain
    entries = [domain] if domain.startswith("www.") else [domain, www_domain]

    def _block():
        hosts_path = Path(hosts_file)
        if not hosts_path.exists():
            raise FileNotFoundError(f"Hosts file not found: {hosts_file}")

        existing = hosts_path.read_text(encoding="utf-8")
        added = []
        skipped = []

        lines_to_add = []
        for entry in entries:
            rule = f"{redirect_ip}\t{entry}"
            # Check if already blocked (any redirect of this domain)
            already_present = any(
                entry in line and not line.strip().startswith("#")
                for line in existing.splitlines()
            )
            if already_present:
                skipped.append(entry)
            else:
                lines_to_add.append(rule)
                added.append(entry)

        if lines_to_add:
            block = (
                    f"\n# EDR DNS block — {domain} — {_now()}\n"
                    + "\n".join(lines_to_add)
                    + "\n"
            )
            with hosts_path.open("a", encoding="utf-8") as f:
                f.write(block)

        # Flush DNS cache so the change takes effect immediately
        flush_result = subprocess.run(
            ["ipconfig", "/flushdns"],
            capture_output=True, text=True
        )
        blacklist(domain, "domain","automatic")
        return {
            "domain": domain,
            "redirect_ip": redirect_ip,
            "hosts_file": str(hosts_path),
            "entries_added": added,
            "entries_skipped_already_blocked": skipped,
            "dns_cache_flushed": flush_result.returncode == 0,
            "flush_stderr": flush_result.stderr.strip() or None,
        }
    return _gate(
        mode, "dns_block", domain,
        f"Block domain '{domain}' via hosts file (redirect → {redirect_ip})",
        _block,
    )

def ip_block(
    ip_address: str,
    mode: Mode = "approval",
    direction: Literal["in", "out", "both"] = "both",
    rule_name: Optional[str] = None,
) -> Dict:
    """
    Block network traffic to/from a specific IP address using Windows Firewall.

    Parameters
    ----------
    ip_address : The IP address to block (IPv4 or IPv6).
    direction  : "inbound" | "outbound" | "both" (default).
    rule_name  : Optional custom rule name. Auto-generated if not provided.
    """
    import re
    IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")
    IPV6_RE = re.compile(r"^[0-9a-fA-F:]+(/\d{1,3})?$")
    if not (IPV4_RE.match(ip_address) or IPV6_RE.match(ip_address)):
        return _result("error", "ip_block", ip_address,
                       {"error": f"Invalid IP address format: '{ip_address}'"})

    base_name = rule_name or f"EDR_BLOCK_{ip_address}_{_now()[:10]}"
    directions = (
        ["in", "out"] if direction == "both" else [direction]
    )

    def _block():
        results = []
        for dir_ in directions:
            name = f"{base_name}_{dir_.upper()}"
            cmd_str = (
                f'netsh advfirewall firewall add rule '
                f'name="{name}" '
                f'dir={dir_} '
                f'action=block '
                f'remoteip={ip_address} '
                f'enable=yes '
                f'profile=any'
            )
            try:
                result = subprocess.run(cmd_str, check=True, capture_output=True, text=True, shell=True)
                results.append({
                    "cmd": cmd_str,
                    "direction": dir_,
                    "rule_name": name,
                    "ok": True,
                    "stdout": result.stdout.strip(),
                })
            except subprocess.CalledProcessError as e:
                results.append({
                    "cmd": cmd_str,
                    "direction": dir_,
                    "rule_name": name,
                    "ok": False,
                    "stderr": e.stderr.strip(),
                })
        blacklist(ip_address,"ip","automatic")
        return {"ip_address": ip_address, "direction": direction, "rules": results}

    return _gate(
        mode, "ip_block", ip_address,
        f"Block {direction} traffic for IP '{ip_address}'",
        _block,
    )

def registry_delete(
    key_path: str,
    mode: Mode = "approval",
    force: bool = False,
) -> Dict:
    """
    Delete a Windows registry key or value, OR delete a scheduled task via schtasks.

    Parameters
    ----------
    key_path : Full registry path. Formats:
               1. Standard key deletion: "HKEY_LOCAL_MACHINE\\Software\\..."
               2. Short form: "HKLM\\Software\\..."
               3. Value deletion: "HKEY_LOCAL_MACHINE\\Software\\key\\@value_name"
               4. Scheduled task deletion: "HKEY_LOCAL_MACHINE\\System\\...\\@schtasks:{task_name}"
                  Special format that triggers schtasks /delete instead of registry deletion.
    mode     : "automatic" | "approval"
    force    : If True, forcefully delete even if doesn't exist (no error).

    Returns
    -------
    Dict with status, action, target, details, and timestamp.
    """
    
    # PROTECTION CHECK: Verify this is not a protected registry key
    is_protected, reason = _protection.is_protected_file(key_path)  # Reuse file protection check
    if is_protected:
        warning_msg = _protection.get_warning("general")
        log.error(f"{warning_msg} - {reason}")
        print(f"\n{'!' * 60}")
        print(f"  {warning_msg}")
        print(f"  Registry Key: {key_path}")
        print(f"  Reason: {reason}")
        print(f"  Action BLOCKED for system safety")
        print(f"{'!' * 60}\n")
        return _result("blocked", "registry_delete", key_path, 
                      {"reason": reason, "warning": warning_msg})
    
    def _delete():
        """Delete registry key/value OR scheduled task via schtasks"""
        # Check for special schtasks format: "...@schtasks:{task_name}"
        if "@schtasks:" in key_path:
            return _delete_scheduled_task(key_path)
        
        # Standard registry deletion
        return _delete_registry(key_path)
    
    def _delete_scheduled_task(key_path: str) -> Dict[str, Any]:
        """
        Delete a scheduled task using schtasks command.
        
        Input format: "HKEY_LOCAL_MACHINE\\System\\...\\@schtasks:{task_name}"
        Extracts task_name and runs: schtasks /delete /tn "task_name" /f
        """
        # Extract task name from format: "...@schtasks:{task_name}"
        parts = key_path.split("@schtasks:", 1)
        if len(parts) < 2:
            raise ValueError(f"Invalid schtasks format: {key_path}")
        
        task_name = parts[1].strip()
        
        # Delete using schtasks command (safer, more appropriate for scheduled tasks)
        cmd = ["schtasks", "/delete", "/tn", task_name, "/f"]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            return {
                "method": "schtasks_cmd",
                "task_name": task_name,
                "command": " ".join(cmd),
                "returncode": result.returncode,
                "success": result.returncode == 0,
                "stdout": result.stdout.strip() or None,
                "stderr": result.stderr.strip() or None,
            }
        except Exception as e:
            raise RuntimeError(f"Failed to delete scheduled task '{task_name}': {e}")
    
    def _delete_registry(key_path: str) -> Dict[str, Any]:
        """Delete registry key/value using winreg module or subprocess"""
        # Normalize key_path: convert short hive names to full names
        hive_mapping = {
            "HKLM": "HKEY_LOCAL_MACHINE",
            "HKCU": "HKEY_CURRENT_USER",
            "HKCR": "HKEY_CLASSES_ROOT",
            "HKU":  "HKEY_USERS",
            "HKCC": "HKEY_CURRENT_CONFIG",
        }
        
        normalized_path = key_path
        for short, full in hive_mapping.items():
            if key_path.upper().startswith(short + "\\"):
                normalized_path = key_path.replace(short, full, 1)
                break
        
        # Check if this is a value deletion (contains @)
        is_value_deletion = "@" in normalized_path
        
        # Split hive and path
        parts = normalized_path.split("\\", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid registry path format: {key_path}")
        
        hive_name = parts[0]
        reg_path = parts[1]
        
        if is_value_deletion:
            # Format: HKEY_...\path\@value_name
            # This DELETES ONLY THE VALUE, not the entire key
            reg_path, value_name = reg_path.rsplit("\\", 1)
            value_name = value_name.lstrip("@")
            return _delete_value(hive_name, reg_path, value_name)
        else:
            # Delete the entire key (careful - use only for malware-dropped keys)
            return _delete_key(hive_name, reg_path)
    
    def _delete_key(hive_name: str, reg_path: str) -> Dict[str, Any]:
        """Delete an entire registry key recursively"""
        hive_map = {
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
            "HKEY_USERS": winreg.HKEY_USERS,
            "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
        }
        
        if hive_name not in hive_map:
            raise ValueError(f"Unknown registry hive: {hive_name}")
        
        hive = hive_map[hive_name]
        
        try:
            # Try using winreg's recursive delete
            def _recursive_delete(hkey: int, key_path: str):
                """Recursively delete a registry key and all subkeys"""
                try:
                    # Open the key
                    key = winreg.OpenKey(hkey, key_path, 0, winreg.KEY_ALL_ACCESS)
                    
                    # Delete all subkeys first
                    while True:
                        try:
                            subkey = winreg.EnumKey(key, 0)
                            _recursive_delete(hkey, f"{key_path}\\{subkey}")
                        except OSError:
                            break  # No more subkeys
                    
                    winreg.CloseKey(key)
                    
                    # Now delete the key itself
                    winreg.DeleteKey(hkey, key_path)
                except OSError as e:
                    if not force:
                        raise
                    # If force=True, ignore errors
                    log.warning(f"Could not delete registry key {key_path}: {e}")
            
            _recursive_delete(hive, reg_path)
            
            return {
                "method": "winreg",
                "deleted_key": f"{hive_name}\\{reg_path}",
                "success": True,
            }
        
        except Exception as e:
            # Fallback: use reg delete command
            log.warning(f"winreg delete failed, trying subprocess: {e}")
            
            hive_short = {
                "HKEY_LOCAL_MACHINE": "HKLM",
                "HKEY_CURRENT_USER": "HKCU",
                "HKEY_CLASSES_ROOT": "HKCR",
                "HKEY_USERS": "HKU",
                "HKEY_CURRENT_CONFIG": "HKCC",
            }.get(hive_name, hive_name)
            
            cmd = ["reg", "delete", f"{hive_short}\\{reg_path}", "/f"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0 or force:
                return {
                    "method": "reg_delete_cmd",
                    "deleted_key": f"{hive_name}\\{reg_path}",
                    "command": " ".join(cmd),
                    "success": result.returncode == 0,
                    "stderr": result.stderr.strip() or None,
                }
            else:
                raise RuntimeError(f"reg delete command failed: {result.stderr}")
    
    def _delete_value(hive_name: str, reg_path: str, value_name: str) -> Dict[str, Any]:
        """Delete a specific registry value within a key"""
        hive_map = {
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
            "HKEY_USERS": winreg.HKEY_USERS,
            "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
        }
        
        if hive_name not in hive_map:
            raise ValueError(f"Unknown registry hive: {hive_name}")
        
        hive = hive_map[hive_name]
        
        try:
            # Try using winreg
            key = winreg.OpenKey(hive, reg_path, 0, winreg.KEY_ALL_ACCESS)
            winreg.DeleteValue(key, value_name)
            winreg.CloseKey(key)
            
            return {
                "method": "winreg",
                "deleted_value": f"{hive_name}\\{reg_path}@{value_name}",
                "success": True,
            }
        
        except Exception as e:
            # Fallback: use reg delete command
            log.warning(f"winreg value delete failed, trying subprocess: {e}")
            
            hive_short = {
                "HKEY_LOCAL_MACHINE": "HKLM",
                "HKEY_CURRENT_USER": "HKCU",
                "HKEY_CLASSES_ROOT": "HKCR",
                "HKEY_USERS": "HKU",
                "HKEY_CURRENT_CONFIG": "HKCC",
            }.get(hive_name, hive_name)
            
            cmd = ["reg", "delete", f"{hive_short}\\{reg_path}", "/v", value_name, "/f"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0 or force:
                return {
                    "method": "reg_delete_cmd",
                    "deleted_value": f"{hive_name}\\{reg_path}@{value_name}",
                    "command": " ".join(cmd),
                    "success": result.returncode == 0,
                    "stderr": result.stderr.strip() or None,
                }
            else:
                raise RuntimeError(f"reg delete command failed: {result.stderr}")
    
    return _gate(mode, "registry_delete", key_path,
                 f"Delete registry key '{key_path}'", _delete)


def identity_revocation(
    identity: str,
    mode: Mode = "approval",
) -> Dict:
    """
    Revoke a compromised user account.
    Parameters
    ----------
    identity      : Username

    """
    def _check_self_lockout():
        """Prevent user from locking themselves out"""
        current_user = getpass.getuser()
        if current_user.lower() == identity.lower():
            raise PermissionError(f"Cannot revoke your own identity '{identity}'. "
                                  f"Use another admin account to revoke this user.")

    def _revoke_windows():
        """Windows implementation using net user command"""
        # Disable the account
        result = subprocess.run(
            ["net", "user", identity, "/active:no"],
            capture_output=True,
            text=True
        )
        return {
            "command": f"net user {identity} /active:no",
            "returncode": result.returncode,
            "stderr": result.stderr,
            "stdout": result.stdout
        }
    # Check for self-lockout before proceeding
    _check_self_lockout()
    revoke_func = _revoke_windows
    return _gate(mode, "identity_revocation", identity,
                 f"Revoke '{identity}' ", revoke_func)
