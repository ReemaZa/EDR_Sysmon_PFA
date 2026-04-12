"""Parsing and normalization for Sysmon events - UPDATED FOR HASH ENGINE."""
from datetime import datetime
from typing import Optional, Dict, Any
import xml.etree.ElementTree as ET
from dateutil import parser as dateparser


# Sysmon Event ID definitions
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
{'computer': 'LAPTOP-LXXX0E',
 'data': {'CommandLine': '"C:\\Program Files (x86)\\Git\\cmd\\git.exe" config '
                         '--get commit.template',
          'Company': 'The Git Development Community',
          'CurrentDirectory': 'D:\\...\\EDR_Sysmon_PFA\\',
          'Description': 'Git for Windows',
          'FileVersion': '2.48.1.windows.1',
          'Hashes': 'MD5=F14A...94E3,SHA256=E0B1A250229E...1A54213BA,IMPHASH=8E06F9..EF5DD6A',
          'Image': 'C:\\Program Files (x86)\\Git\\cmd\\git.exe',
          'IntegrityLevel': 'High',
          'LogonGuid': '{e36f5...0000000}',
          'LogonId': '0x20db66',
          'OriginalFileName': 'git.exe',
          'ParentCommandLine': '"C:\\Users\\RimaZ\\AppData\\Local\\Programs\\Microsoft '
                               'VS Code\\_\\Code.exe" --type=utility '
                               '--utility-sub-type=node......',
          'ParentImage': 'C:\\Users\\RimaZ\\AppData\\Local\\Programs\\Microsoft '
                         'VS Code\\_\\Code.exe',
          'ParentProcessGuid': '{e36f5e2e-...01200}',
          'ParentProcessId': '3416',
          'ParentUser': 'LAPTOP-L..0E\\RimaZ',
          'ProcessGuid': '{e36f5e2e-...1200}',
          'ProcessId': '31188',
          'Product': 'Git',
          'RuleName': '-',
          'TerminalSessionId': '1',
          'User': 'LAPTOP-LXXX0E\\RimaZ',
          'UtcTime': '2026-04-12 13:01:04.052'},
           # Parsed fields (for hash engine - moved to root level)
          'hashes': {'md5': 'abc', 'sha256': 'def'} 
 'event_id': 1,
 'timestamp': '2026-04-12T13:01:04.0573165Z'}

'''

def parse_hashes(hash_string: str) -> Dict[str, str]:
    """
    Parse Sysmon hash field (format: MD5=...,SHA256=...,IMPHASH=...)
    
    Args:
        hash_string: Hashes field from Sysmon event
        
    Returns:
        Dict with hash type as key, hash value as value (lowercase)
        
    Example:
        Input:  "MD5=ABC123,SHA256=DEF456"
        Output: {'md5': 'abc123', 'sha256': 'def456'}
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
    """
    Parse Sysmon event XML and extract key information.
    
    OUTPUT FORMAT:
    {
        'timestamp': '2024-01-15 10:30:45',
        'event_id': 1,
        'computer': 'DESKTOP-01',
        'data': {
            # Raw fields (for Sigma engine - untouched)
            'Image': 'C:\\Windows\\cmd.exe',
            'CommandLine': 'cmd.exe /c malware',
            'Hashes': 'MD5=abc,SHA256=def',  # ← Raw string
        },
        # Parsed fields (for hash engine - moved to root level)
        'hashes': {'md5': 'abc', 'sha256': 'def'} 
    }
    """
    try:
        root = ET.fromstring(xml_string)
        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

        system = root.find('.//ns:System', ns)
        event_data = root.find('.//ns:EventData', ns)

        if system is None or event_data is None:
            return None

        # Parse timestamp
        time_created = system.find('.//ns:TimeCreated', ns)
        timestamp = time_created.get('SystemTime') if time_created is not None else 'Unknown'
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            pass

        # Get event ID
        event_id_elem = system.find('.//ns:EventID', ns)
        event_id = event_id_elem.text if event_id_elem is not None else 'Unknown'

        # Get computer name
        computer_elem = system.find('.//ns:Computer', ns)
        computer = computer_elem.text if computer_elem is not None else 'Unknown'

        # Extract all data fields
        data_fields = {}
        for data in event_data.findall('.//ns:Data', ns):
            name = data.get('Name')
            text = data.text if data.text else ''
            data_fields[name] = text
        
        # Build the base result dictionary
        result = {
            'timestamp': timestamp,
            'event_id': int(event_id),
            'computer': computer,
            'event_type': SYSMON_EVENTS[int(event_id)],
            'data': data_fields
        }

        # ========================================================================
        # CRITICAL FIX: Parse hashes for hash engine
        # ========================================================================
        # If event has 'Hashes' field (raw string), parse it and add to the ROOT level
        if 'Hashes' in data_fields:
            raw_hashes = data_fields['Hashes']
            result['hashes'] = parse_hashes(raw_hashes)
        
        return result
    
    except Exception as e:
        print(f"[!] Parse error: {e}")
        return None