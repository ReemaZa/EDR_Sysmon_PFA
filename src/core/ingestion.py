"""Parsing and normalization for Sysmon events."""
from datetime import datetime
from typing import Optional, Dict, Any
import xml.etree.ElementTree as ET
from dateutil import parser as dateparser


# Sysmon Event ID definitions for reference
SYSMON_EVENTS = {
    1: "Process Create",
    2: "A process changed a file creation time",
    3: "Network connection detected",
    5: "Process terminated",
    6: "Driver loaded",
    7: "Image loaded",
    8: "CreateRemoteThread detected",
    9: "RawAccessThread detected",
    10: "Process accessed",
    11: "FileCreate detected",
    12: "Registry object added or deleted",
    13: "Registry value set",
    14: "Registry object renamed",
    15: "FileCreateStreamHash detected",
    17: "Pipe Created",
    18: "Pipe Connected",
    19: "WmiEvent: WmiEventFilter activity detected",
    20: "WmiEvent: WmiEventConsumer activity detected",
    21: "WmiEvent: WmiEventConsumerToFilter activity detected",
    22: "DNSQuery detected",
    23: "FileDelete detected",
    24: "Clipboard data captured",
    25: "Process tampering detected",
    26: "Hmodule load detected",
    27: "HostImport library load detected",
    28: "Error in raw access thread",
}

'''
example of output after parsing 
{
    "event_id": 1,
    "event_type": "Process Create",
    "timestamp": "2024-05-20T14:30:05.123456+00:00",
    "computer": "DESKTOP-SEC-01",
    "provider": "Microsoft-Windows-Sysmon",
    "event_record_id": 4502,
    "user_id": "S-1-5-18",
    "execution": {
        "process_id": "1200",
        "thread_id": "1204"
    },
    "rule_name": "technique_id=T1059,technique_name=Command and Scripting Interpreter",
    "data": {
        "process": {
            "image": "c:/windows/system32/cmd.exe",
            "command_line": '"cmd.exe" /c echo hello',
            "current_directory": "",
            "pid": "", # Note: Filled only if 'ProcessId' exists in EventData
            "guid": "",
            "user": "WORKGROUP\\Admin",
            "logon_id": "",
            "logon_guid": "",
            "terminal_session_id": "",
            "integrity_level": ""
        },
        "parent_process": {
            "image": "c:/windows/explorer.exe",
            "command_line": "",
            "pid": "",
            "guid": "",
            "user": ""
        },
        "hashes": {
            "md5": "5bd75956a040b136d2140d8c570a5c22",
            "sha256": "270a9f3ff36979a03a4e3150860bd41697c6f2a5ba12480d9616d8a29a3a2c89"
        }
    },
    "raw_data": {
        "RuleName": "technique_id=T1059,technique_name=Command and Scripting Interpreter",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "\"cmd.exe\" /c echo hello",
        "Hashes": "MD5=5BD75956A040B136D2140D8C570A5C22,SHA256=270A9F3FF36979A03A4E3150860BD41697C6F2A5BA12480D9616D8A29A3A2C89",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "User": "WORKGROUP\\Admin"
    }
}
'''

def parse_hashes(hash_string: str) -> Dict[str, str]:
    """
    Parse Sysmon hash field (format: MD5=...,SHA256=...,IMPHASH=...)
    
    Args:
        hash_string: Hashes field from Sysmon event
        
    Returns:
        Dict with hash type as key, hash value as value
    """
    hashes = {}
    if not hash_string or hash_string == "-":
        return hashes
    
    for hash_pair in hash_string.split(","):
        if "=" in hash_pair:
            hash_type, hash_value = hash_pair.split("=", 1)
            hashes[hash_type.lower()] = hash_value.lower()
    
    return hashes


def normalize_path(path: str) -> str:
    """Normalize file paths for consistency."""
    if not path:
        return ""
    return path.replace("\\", "/").lower()


def parse_sysmon_event(xml_string):
    """Parse Sysmon event XML and extract key information."""
    try:
        root = ET.fromstring(xml_string)
        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

        system = root.find('.//ns:System', ns)
        event_data = root.find('.//ns:EventData', ns)

        if system is None or event_data is None:
            return None

        time_created = system.find('.//ns:TimeCreated', ns)
        timestamp = time_created.get('SystemTime') if time_created is not None else 'Unknown'
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            pass

        event_id_elem = system.find('.//ns:EventID', ns)
        event_id = event_id_elem.text if event_id_elem is not None else 'Unknown'

        computer_elem = system.find('.//ns:Computer', ns)
        computer = computer_elem.text if computer_elem is not None else 'Unknown'

        data_fields = {}
        for data in event_data.findall('.//ns:Data', ns):
            name = data.get('Name')
            text = data.text if data.text else ''
            data_fields[name] = text
        
        return {
            'timestamp': timestamp,
            'event_id': int(event_id),
            'computer': computer,
            'data': data_fields
        }
    except Exception as e:
        print(f"[!] Parse error: {e}")
        return None