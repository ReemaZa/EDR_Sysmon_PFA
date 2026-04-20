"""
EDR AI Agent Response Functions
Supports two modes for every action:
  - automatic : executes immediately (for high-confidence, time-critical automation)
  - approval  : prints a structured request and waits for operator confirmation

Every function returns a dict with keys:
  status   : "executed" | "pending_approval" | "approved" | "rejected" | "error"
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

"""
import datetime
import getpass
import hashlib
import json
import logging
import os
import shutil
import signal
import subprocess
from pathlib import Path
from typing import Any, Dict, Literal, Optional

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [EDR] %(levelname)s %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger("edr")

Mode = Literal["automatic", "approval"]

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


def _gate(mode: Mode, action: str, target: str, description: str,
          execute_fn, *args, **kwargs) -> Dict:
    """
    Central dispatch: automatic executes immediately; approval blocks until
    the operator responds, then executes or aborts.
    """
    if mode == "automatic":
        try:
            details = execute_fn(*args, **kwargs)
            return _result("executed", action, target, details)
        except Exception as exc:
            return _result("error", action, target, {"error": str(exc)})

    # approval mode
    approved = _request_approval(action, target, description)
    if not approved:
        return _result("rejected", action, target, {"reason": "operator_rejected"})
    try:
        details = execute_fn(*args, **kwargs)
        return _result("approved", action, target, details)
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
    def _terminate():
        try:
            import psutil
            proc = psutil.Process(pid)
            info = {"name": proc.name(), "exe": proc.exe(), "cmdline": proc.cmdline()}
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

    Requirements
    -------------------------
    - Root / Administrator privileges on the target.
    - Network access to patch repo (conflicts with host_isolation — sequence carefully).
    - Compatibility testing: blind patching can break dependent services.
    - Reboot handling: kernel and many Windows patches require restart.
    - 0-day: if no patch exists, compensating controls (isolation, WAF rule,
      virtual patching via IDS signature) are required in the interim.

    Recommended flow:
      isolate -> patch -> health-check -> release isolation
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
