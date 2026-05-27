"""
EDR Sysmon Dashboard - Web UI
Flask-based interface for monitoring threat detection
"""

from flask import Flask, render_template, jsonify, request
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
from src.detection.l4_llm_detection.action_executor import ActionExecutor

_executor = ActionExecutor(mode="automatic")

app = Flask(__name__, template_folder='templates', static_folder='static')

# Configuration — resolve relative to this file's location
DATA_DIR = Path(__file__).parent.parent
ACTION_LOG = DATA_DIR / 'action_log.jsonl'
HASH_BLACKLIST   = DATA_DIR / 'config' / 'ioc' / 'hash_blacklist.txt'
DOMAIN_BLACKLIST = DATA_DIR / 'config' / 'ioc' / 'domain_blacklist.txt'
IP_BLACKLIST     = DATA_DIR / 'config' / 'ioc' / 'ip_blacklist.txt'
AGENT_BLACKLIST     = DATA_DIR / 'config' / 'ioc' / 'agent_blacklist.json'
PENDING_APPROVALS   = DATA_DIR / 'pending_approvals.jsonl'

# ─── Action-type → detection layer mapping ────────────────────────────────────
ACTION_LAYER_MAP = {
    'process_termination': 'Process',
    'file_quarantine':     'File',
    'file_deletion':       'File',
    'ip_block':            'Network',
    'dns_block':           'Network',
    'identity_revocation': 'Identity',
    'patching':            'Patch',
    'blacklist':           'IOC',
    'alert':               'Alert',
    'nothing':             'Noop',
}

# ─── Severity inference ────────────────────────────────────────────────────────
def _infer_severity(action: dict) -> str:
    """
    Derive a threat level from an action entry.
    Priority: explicit severity field > action type > status.
    """
    # Some alert actions carry explicit severity
    details = action.get('details') or {}
    explicit = (
        details.get('severity') or
        details.get('threat_level') or
        action.get('threat_level') or
        action.get('severity')
    )
    if explicit:
        return explicit.upper()

    action_type = action.get('action') or action.get('type', '')
    status = action.get('status', '')

    # Network / credential actions are high-confidence threats
    if action_type in ('ip_block', 'dns_block', 'identity_revocation'):
        return 'HIGH'
    if action_type in ('file_quarantine', 'file_deletion', 'process_termination'):
        return 'MEDIUM' if status == 'error' else 'HIGH'
    if action_type == 'blacklist':
        return 'MEDIUM'
    if action_type == 'alert':
        return 'HIGH'
    if status == 'error':
        return 'LOW'
    return 'LOW'


def _flatten_log() -> list[dict]:
    """
    Parse action_log.jsonl.

    Each line is a JSON object with shape:
        { "anchor": "...", "actions": [ { "action": ..., "status": ..., ... }, ... ] }

    We explode every action entry into a flat alert record the dashboard can consume.
    """
    alerts = []
    if not ACTION_LOG.exists():
        return alerts

    try:
        with open(ACTION_LOG, 'r', encoding='utf-8') as f:
            for lineno, raw in enumerate(f, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    record = json.loads(raw)
                except json.JSONDecodeError as exc:
                    print(f"[WARN] line {lineno}: JSON parse error — {exc}")
                    continue

                anchor = record.get('anchor', 'unknown')
                actions = record.get('actions', [])

                # Support both nested-actions format AND legacy flat format
                if not actions and 'action' in record:
                    actions = [record]

                for idx, action in enumerate(actions):
                    action_type  = action.get('action') or action.get('type', 'unknown')
                    status       = action.get('status', 'unknown')
                    target       = action.get('target', '')
                    details      = action.get('details') or {}
                    timestamp    = (
                        action.get('timestamp') or
                        details.get('timestamp') or
                        record.get('timestamp', '')
                    )
                    threat_level = _infer_severity(action)
                    layer        = ACTION_LAYER_MAP.get(action_type, 'Other')

                    # Build a human-readable message
                    if status == 'error':
                        err = (
                            action.get('error') or
                            details.get('error') or
                            'Unknown error'
                        )
                        message = f"{action_type} failed on '{target}': {err}"
                    elif status == 'skipped':
                        reason = details.get('reason', 'No reason given')
                        message = f"{action_type} skipped: {reason}"
                    else:
                        message = details.get('message') or f"{action_type} executed on '{target}'"

                    alerts.append({
                        'id':           f"{anchor}-{lineno}-{idx}",
                        'anchor':       anchor,
                        'action':       action_type,
                        'status':       status,
                        'target':       target,
                        'threat_level': threat_level,
                        'layer':        layer,
                        'message':      message,
                        'timestamp':    timestamp,
                        'details':      details,
                        'raw':          action,          # keep original for debugging
                    })

    except Exception as exc:
        print(f"[ERROR] reading action log: {exc}")

    # Most-recent first
    return sorted(alerts, key=lambda x: x.get('timestamp', ''), reverse=True)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _is_recent(timestamp_str: str, hours: int = 24) -> bool:
    if not timestamp_str:
        return False
    try:
        ts = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        return datetime.now(ts.tzinfo) - ts < timedelta(hours=hours)
    except Exception:
        return False


def _get_statistics(alerts: list[dict]) -> dict:
    by_level = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    by_action: dict[str, int] = {}
    by_status: dict[str, int] = {}
    last_24h = 0

    for a in alerts:
        lvl = a.get('threat_level', 'LOW')
        by_level[lvl] = by_level.get(lvl, 0) + 1

        action = a.get('action', 'unknown')
        by_action[action] = by_action.get(action, 0) + 1

        st = a.get('status', 'unknown')
        by_status[st] = by_status.get(st, 0) + 1

        if _is_recent(a.get('timestamp', ''), 24):
            last_24h += 1

    return {
        'total_alerts': len(alerts),
        'critical':     by_level.get('CRITICAL', 0),
        'high':         by_level.get('HIGH', 0),
        'medium':       by_level.get('MEDIUM', 0),
        'low':          by_level.get('LOW', 0),
        'by_action':    by_action,
        'by_status':    by_status,
        'last_24h':     last_24h,
    }


def _read_txt_list(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        with open(path, 'r') as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith('#')]
    except Exception as exc:
        print(f"[ERROR] reading {path}: {exc}")
        return []

def _append_txt_list(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'a') as f:
        f.write(value + "\n")

def _get_blacklist_stats() -> dict:
    hashes = _read_txt_list(HASH_BLACKLIST)
    return {'count': len(hashes), 'hashes': hashes[:10]}

def _get_domain_blacklist_stats() -> dict:
    domains = _read_txt_list(DOMAIN_BLACKLIST)
    return {'count': len(domains), 'domains': domains[:10]}

def _get_ip_blacklist_stats() -> dict:
    ips = _read_txt_list(IP_BLACKLIST)
    return {'count': len(ips), 'ips': ips[:10]}

def _get_agent_blacklist_stats() -> dict:
    if not AGENT_BLACKLIST.exists():
        return {'count': 0, 'entries': []}
    try:
        with open(AGENT_BLACKLIST, 'r') as f:
            data = json.load(f)
        entries = data if isinstance(data, list) else data.get('entries', [])
        return {'count': len(entries), 'entries': entries[:10]}
    except Exception as exc:
        print(f"[ERROR] reading agent blacklist: {exc}")
        return {'count': 0, 'entries': [], 'error': str(exc)}


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def dashboard():
    return render_template('dashboard.html')


@app.route('/api/statistics')
def api_statistics():
    alerts = _flatten_log()
    return jsonify(_get_statistics(alerts))


@app.route('/api/alerts')
def api_alerts():
    alerts = _flatten_log()

    severity = request.args.get('severity', 'all').upper()
    if severity != 'ALL':
        alerts = [a for a in alerts if a.get('threat_level') == severity]

    status = request.args.get('status', 'all')
    if status != 'all':
        alerts = [a for a in alerts if a.get('status') == status]

    # Strip the raw field from the API response to keep payload small
    clean = [{k: v for k, v in a.items() if k != 'raw'} for a in alerts]

    page     = max(1, int(request.args.get('page', 1)))
    per_page = max(1, int(request.args.get('per_page', 20)))
    start    = (page - 1) * per_page
    end      = start + per_page

    return jsonify({
        'alerts':   clean[start:end],
        'total':    len(clean),
        'page':     page,
        'per_page': per_page,
    })


@app.route('/api/layers')
def api_layers():
    """Return distinct detection layers present in the log."""
    alerts = _flatten_log()
    layers = sorted({a.get('layer', 'Other') for a in alerts})
    return jsonify({'layers': layers})


@app.route('/api/blacklist', methods=['GET'])
def api_blacklist():
    return jsonify(_get_blacklist_stats())


@app.route('/api/blacklist', methods=['POST'])
def api_add_hash():
    data       = request.get_json(force=True) or {}
    hash_value = data.get('hash', '').strip()
    if not hash_value:
        return jsonify({'error': 'Hash cannot be empty'}), 400
    try:
        _append_txt_list(HASH_BLACKLIST, hash_value)
        return jsonify({'success': True, 'message': 'Hash added to blacklist'})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


@app.route('/api/domain-blacklist', methods=['GET'])
def api_domain_blacklist():
    return jsonify(_get_domain_blacklist_stats())


@app.route('/api/domain-blacklist', methods=['POST'])
def api_add_domain():
    data  = request.get_json(force=True) or {}
    value = data.get('domain', '').strip()
    if not value:
        return jsonify({'error': 'Domain cannot be empty'}), 400
    try:
        _append_txt_list(DOMAIN_BLACKLIST, value)
        return jsonify({'success': True, 'message': 'Domain added to blacklist'})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


@app.route('/api/ip-blacklist', methods=['GET'])
def api_ip_blacklist():
    return jsonify(_get_ip_blacklist_stats())


@app.route('/api/ip-blacklist', methods=['POST'])
def api_add_ip():
    data  = request.get_json(force=True) or {}
    value = data.get('ip', '').strip()
    if not value:
        return jsonify({'error': 'IP cannot be empty'}), 400
    try:
        _append_txt_list(IP_BLACKLIST, value)
        return jsonify({'success': True, 'message': 'IP added to blacklist'})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


@app.route('/api/agent-blacklist', methods=['GET'])
def api_agent_blacklist():
    return jsonify(_get_agent_blacklist_stats())


@app.route('/api/agent-blacklist', methods=['POST'])
def api_add_agent():
    data  = request.get_json(force=True) or {}
    entry = data.get('entry')
    if not entry:
        return jsonify({'error': 'Entry cannot be empty'}), 400
    try:
        AGENT_BLACKLIST.parent.mkdir(parents=True, exist_ok=True)
        existing = []
        if AGENT_BLACKLIST.exists():
            with open(AGENT_BLACKLIST, 'r') as f:
                raw = json.load(f)
            existing = raw if isinstance(raw, list) else raw.get('entries', [])
        existing.append(entry)
        with open(AGENT_BLACKLIST, 'w') as f:
            json.dump(existing, f, indent=2)
        return jsonify({'success': True, 'message': 'Agent entry added to blacklist'})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500



# ─── Pending Approvals helpers ────────────────────────────────────────────────

def _load_approvals() -> list[dict]:
    """Parse pending_approvals.jsonl — each line is one investigation record."""
    records = []
    if not PENDING_APPROVALS.exists():
        return records
    try:
        with open(PENDING_APPROVALS, 'r', encoding='utf-8') as f:
            for lineno, raw in enumerate(f, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    records.append(json.loads(raw))
                except json.JSONDecodeError as exc:
                    print(f"[WARN] pending_approvals line {lineno}: {exc}")
    except Exception as exc:
        print(f"[ERROR] reading pending_approvals: {exc}")
    return records


def _save_approvals(records: list[dict]) -> None:
    PENDING_APPROVALS.parent.mkdir(parents=True, exist_ok=True)
    with open(PENDING_APPROVALS, 'w', encoding='utf-8') as f:
        for rec in records:
            f.write(json.dumps(rec) + '\n')


@app.route('/api/approvals', methods=['GET'])
def api_approvals():
    """Return all pending approval records."""
    records = _load_approvals()
    return jsonify({'records': records, 'total': len(records)})


@app.route('/api/approvals/<analysis_id>/actions/<action_id>/approve', methods=['POST'])
def api_approve_action(analysis_id, action_id):
    return _set_action_decision(analysis_id, action_id, 'approved')


@app.route('/api/approvals/<analysis_id>/actions/<action_id>/reject', methods=['POST'])
def api_reject_action(analysis_id, action_id):
    return _set_action_decision(analysis_id, action_id, 'rejected')


def _set_action_decision(analysis_id: str, action_id: str, decision: str):
    records = _load_approvals()
    for rec in records:
        if rec.get('analysis_id') != analysis_id:
            continue
        for action in rec.get('actions', []):
            if action.get('id') == action_id:
                action['decision'] = decision
                _save_approvals(records)

                # Execute immediately if approved — single action, already human-approved
                if decision == 'approved':
                    anchor = rec.get('anchor_guid', analysis_id)
                    _executor.execute_async([action], anchor_guid=anchor)

                return jsonify({'success': True, 'decision': decision,
                                'analysis_id': analysis_id, 'action_id': action_id})
    return jsonify({'error': 'action not found'}), 404





if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)