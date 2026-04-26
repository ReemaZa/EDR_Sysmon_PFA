# src/detection/findings.py

import json
import redis

_client = None

def _get_client() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.Redis(
            host="localhost",
            port=6379,
            db=0,
            decode_responses=True,
            socket_connect_timeout=5,
            retry_on_timeout=True,
        )
    return _client


def get_finding_titles(finding_ids: list) -> dict:
    """
    finding_ids: ["uuid-1042", "uuid-2201", ...]

    Each finding is stored in Redis as:
        key   = "finding:{rule_id}"
        value = JSON string: {rule_id, title, score, techniques, tactics}

    Returns: {"uuid-1042": "Encoded PowerShell Execution", ...}
    """
    if not finding_ids:
        return {}

    r    = _get_client()
    keys = [f"finding:{fid}" for fid in finding_ids]

    pipe    = r.pipeline()
    for key in keys:
        pipe.get(key)
    results = pipe.execute()

    out = {}
    for fid, raw in zip(finding_ids, results):
        if raw:
            try:
                data = json.loads(raw)
                out[fid] = data.get("title", "Unknown Finding")
            except json.JSONDecodeError:
                out[fid] = "Unknown Finding"
        else:
            out[fid] = "Unknown Finding"

    return out


def get_finding(finding_id: str) -> dict | None:
    """
    Returns the full finding dict for a single ID:
    {rule_id, title, score, techniques, tactics}
    """
    r   = _get_client()
    raw = r.get(f"finding:{finding_id}")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None