"""Parsing and normalization for Sysmon events."""
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


def parse_sysmon_event(event_xml: str) -> Optional[Dict[str, Any]]:
    """
    Parse a Sysmon event XML string into a normalized, structured dict.
    
    This parser intelligently extracts fields and structures them for:
    - Hash scanning (MD5, SHA256, IMPHASH)
    - Sigma rules matching
    - YARA rule conditions
    
    Args:
        event_xml: Raw XML string from win32evtlog.EvtRender()

    Returns:
        Dict with normalized Sysmon event data, or None if parsing fails
    """
    try:
        root = ET.fromstring(event_xml)
    except ET.ParseError:
        return None

    # XML namespace for Windows Event Log
    ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'

    # Extract System section
    system = root.find(f'.//{ns}System')
    if system is None:
        return None

    # === SYSTEM FIELDS ===
    
    # EventID
    event_id_node = system.find(f'{ns}EventID')
    event_id = int(event_id_node.text) if event_id_node is not None and event_id_node.text else -1
    
    # Event type name for convenience
    event_type = SYSMON_EVENTS.get(event_id, f"Unknown Event {event_id}")

    # Timestamp - normalize to ISO format
    time_node = system.find(f'{ns}TimeCreated')
    timestamp = time_node.get('SystemTime') if time_node is not None else None
    if timestamp:
        try:
            dt = dateparser.parse(timestamp)
            timestamp = dt.isoformat()
        except Exception:
            pass  # Keep original format if parsing fails

    # Computer name
    computer_node = system.find(f'{ns}Computer')
    computer = computer_node.text if computer_node is not None else ""

    # Provider/Channel name
    provider_node = system.find(f'{ns}Provider')
    provider = provider_node.get('Name') if provider_node is not None else "Unknown"

    # Event Record ID
    event_record_id_node = system.find(f'{ns}EventRecordID')
    event_record_id = int(event_record_id_node.text) if event_record_id_node is not None else 0

    # Execution info (ProcessID, ThreadID)
    execution_node = system.find(f'{ns}Execution')
    execution_process_id = execution_node.get('ProcessID') if execution_node is not None else ""
    execution_thread_id = execution_node.get('ThreadID') if execution_node is not None else ""

    # User
    security_node = system.find(f'{ns}Security')
    user_id = security_node.get('UserID') if security_node is not None else ""

    # === EVENT DATA FIELDS ===
    
    # Extract EventData section and build a structured dict
    event_data_node = root.find(f'.//{ns}EventData')
    event_data_raw = {}
    
    if event_data_node is not None:
        for d in event_data_node.findall(f'{ns}Data'):
            name = d.get('Name')
            text = d.text or ''
            if name:
                event_data_raw[name] = text

    # === PARSED EVENT DATA (Intelligently structured) ===
    
    parsed_data = {}
    
    # Process Information (Event ID 1, 3, 10, etc.)
    if 'Image' in event_data_raw:
        parsed_data['process'] = {
            'image': normalize_path(event_data_raw.get('Image', '')),
            'command_line': event_data_raw.get('CommandLine', ''),
            'current_directory': normalize_path(event_data_raw.get('CurrentDirectory', '')),
            'pid': event_data_raw.get('ProcessId', ''),
            'guid': event_data_raw.get('ProcessGuid', ''),
            'user': event_data_raw.get('User', ''),
            'logon_id': event_data_raw.get('LogonId', ''),
            'logon_guid': event_data_raw.get('LogonGuid', ''),
            'terminal_session_id': event_data_raw.get('TerminalSessionId', ''),
            'integrity_level': event_data_raw.get('IntegrityLevel', ''),
        }
    
    # Parent Process Information
    if 'ParentImage' in event_data_raw:
        parsed_data['parent_process'] = {
            'image': normalize_path(event_data_raw.get('ParentImage', '')),
            'command_line': event_data_raw.get('ParentCommandLine', ''),
            'pid': event_data_raw.get('ParentProcessId', ''),
            'guid': event_data_raw.get('ParentProcessGuid', ''),
            'user': event_data_raw.get('ParentUser', ''),
        }
    
    # File Information (Event ID 11, 23, etc.)
    if 'TargetFilename' in event_data_raw:
        parsed_data['file'] = {
            'path': normalize_path(event_data_raw.get('TargetFilename', '')),
            'creation_time': event_data_raw.get('CreationUtcTime', ''),
            'previous_creation_time': event_data_raw.get('PreviousCreationUtcTime', ''),
        }
    
    # Hash Information (Critical for hash scanning)
    if 'Hashes' in event_data_raw:
        parsed_data['hashes'] = parse_hashes(event_data_raw.get('Hashes', ''))
    
    # File Version Information (for file scanning)
    if 'FileVersion' in event_data_raw or 'Product' in event_data_raw:
        parsed_data['file_version'] = {
            'file_version': event_data_raw.get('FileVersion', ''),
            'product': event_data_raw.get('Product', ''),
            'company': event_data_raw.get('Company', ''),
            'description': event_data_raw.get('Description', ''),
            'original_file_name': event_data_raw.get('OriginalFileName', ''),
        }
    
    # Network Information (Event ID 3)
    if 'DestinationIp' in event_data_raw:
        parsed_data['network'] = {
            'source_ip': event_data_raw.get('SourceIp', ''),
            'source_port': event_data_raw.get('SourcePort', ''),
            'destination_ip': event_data_raw.get('DestinationIp', ''),
            'destination_port': event_data_raw.get('DestinationPort', ''),
            'protocol': event_data_raw.get('Protocol', ''),
            'initiated': event_data_raw.get('Initiated', ''),
            'source_is_ipv6': event_data_raw.get('SourceIsIpv6', ''),
            'destination_is_ipv6': event_data_raw.get('DestinationIsIpv6', ''),
        }
    
    # DNS Query Information (Event ID 22)
    if 'QueryName' in event_data_raw:
        parsed_data['dns'] = {
            'query_name': event_data_raw.get('QueryName', '').lower(),
            'query_status': event_data_raw.get('QueryStatus', ''),
            'query_results': event_data_raw.get('QueryResults', ''),
        }
    
    # Registry Information (Event ID 12, 13, 14)
    if 'TargetObject' in event_data_raw:
        parsed_data['registry'] = {
            'target_object': event_data_raw.get('TargetObject', ''),
            'event_type': event_data_raw.get('EventType', ''),
            'details': event_data_raw.get('Details', ''),
        }
    
    # Pipe Information (Event ID 17, 18)
    if 'PipeName' in event_data_raw:
        parsed_data['pipe'] = {
            'name': event_data_raw.get('PipeName', ''),
        }
    
    # Image Load Information (Event ID 7)
    if 'ImageLoaded' in event_data_raw:
        parsed_data['image_load'] = {
            'image_loaded': normalize_path(event_data_raw.get('ImageLoaded', '')),
            'signed': event_data_raw.get('Signed', ''),
            'signature': event_data_raw.get('Signature', ''),
            'signature_status': event_data_raw.get('SignatureStatus', ''),
        }
    
    # Driver Load Information (Event ID 6)
    if 'ImageLoaded' in event_data_raw and event_id == 6:
        parsed_data['driver'] = {
            'image_loaded': normalize_path(event_data_raw.get('ImageLoaded', '')),
            'hashes': parse_hashes(event_data_raw.get('Hashes', '')),
            'signed': event_data_raw.get('Signed', ''),
        }
    
    # Rule Name (present in most events for better organization)
    rule_name = event_data_raw.get('RuleName', '-')
    
    # === BUILD FINAL NORMALIZED EVENT ===
    
    return {
        # System fields
        "event_id": event_id,
        "event_type": event_type,
        "timestamp": timestamp or "",
        "computer": computer,
        "provider": provider,
        "event_record_id": event_record_id,
        "user_id": user_id,
        "execution": {
            "process_id": execution_process_id,
            "thread_id": execution_thread_id,
        },
        
        # Rule and metadata
        "rule_name": rule_name,
        
        # Parsed structured data (for Sigma, YARA, hash scanning)
        "data": parsed_data,
        
        # Raw event data (fallback for fields not explicitly parsed)
        "raw_data": event_data_raw,
    }
