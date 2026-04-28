ATTACK SCENARIO — FULL CHAIN DESCRIPTION
==========================================
Machine  : DESKTOP-GK7F3A2.corp.internal
User     : CORP\Gabr  →  escalates to CORP\Administrator
Timeframe: 2024-03-14 08:21 – 08:28

------------------------------------------
STEP 1a — Initial Access (Event ID 1: ProcessCreate)
------------------------------------------
IDM.exe executed from the Downloads folder by explorer.exe.
No version info, no company — unsigned dropped binary masquerading
as a legitimate tool. Runs at Medium integrity under CORP\Gabr.
ProcessGuid : {A3C21F08-1A04-65F2-BB00-000000009401}
ProcessId   : 5736

------------------------------------------
STEP 1b — C2 Beacon (Event ID 3: NetworkConnect)
------------------------------------------
IDM.exe immediately beacons out to attacker-kali.local (10.0.0.10)
on port 4444 over TCP — classic Metasploit/nc reverse shell port.
Same ProcessGuid as step 1a confirms it is IDM.exe making the call.

------------------------------------------
STEP 2a — Reverse Shell Spawns cmd.exe (Event ID 1: ProcessCreate)
------------------------------------------
IDM.exe spawns cmd.exe through the reverse shell channel.
Runs at Medium integrity, same logon session as Gabr.
ProcessGuid : {A3C21F08-1B11-65F2-CC00-000000009401}
ProcessId   : 6012
Parent      : IDM.exe PID 5736

------------------------------------------
STEP 2b — UAC Bypass Registry Write (Event ID 13: RegistrySetValue)
------------------------------------------
cmd.exe writes a malicious command into the fodhelper UAC bypass key:
HKCU\Software\Classes\ms-settings\shell\open\command\sEpQhpkr
Value contains an encoded PowerShell one-liner (SQBFAFgA = IEX base64).
This poisons the registry so that launching fodhelper.exe will
silently execute the attacker payload at High integrity.
Same ProcessGuid as step 2a confirms cmd.exe is the writer.

------------------------------------------
STEP 2c — UAC Bypass Triggers fodhelper.exe (Event ID 1: ProcessCreate)
------------------------------------------
cmd.exe launches fodhelper.exe. Windows auto-elevates it to High
integrity without a UAC prompt because it is a trusted Microsoft binary.
fodhelper reads the poisoned registry key and executes the payload.
ProcessGuid : {A3C21F08-1B12-65F2-DD00-000000009401}
ProcessId   : 6204
IntegrityLevel: High
Parent      : cmd.exe PID 6012

------------------------------------------
STEP 3 — Tool Drop (Event ID 11: FileCreate)
------------------------------------------
IDM.exe writes mimikatz.exe to disk at:
C:\Users\Gabr\Downloads\mimikatz.exe
RuleName T1105 (Ingress Tool Transfer) fired by Sysmon config.
ProcessGuid matches IDM.exe — the C2 channel delivered the binary.

------------------------------------------
STEP 3b — mimikatz.exe Launched (Event ID 1: ProcessCreate)
------------------------------------------
fodhelper.exe (now elevated) executes mimikatz.exe with the
Pass-the-Hash command inline:
  sekurlsa::pth /user:Administrator /domain:CORP /ntlm:A29F7... /run:powershell.exe
Runs at High integrity — elevation from step 2c carried forward.
ProcessGuid : {A3C21F08-1C22-65F2-EE00-000000009401}
ProcessId   : 4988
Parent      : fodhelper.exe PID 6204

------------------------------------------
STEP 4 — Credential Dumping (Event ID 10: ProcessAccess)
------------------------------------------
mimikatz.exe opens lsass.exe with GrantedAccess 0x1010
(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION).
CallTrace confirms the read originates inside mimikatz code sections.
RuleName T1003 (Credential Dumping) fired.
SourceProcessGuid : {A3C21F08-1C22-65F2-EE00-000000009401}  ← mimikatz
TargetProcessGuid : {A3C21F08-0A11-65F2-0800-000000009401}  ← lsass PID 688

------------------------------------------
STEP 5 — Pass-the-Hash → Elevated Shell (Event ID 1: ProcessCreate)
------------------------------------------
mimikatz sekurlsa::pth spawns powershell.exe under the
CORP\Administrator identity using the stolen NTLM hash.
No password needed — token impersonation only.
User shifts from CORP\Gabr to CORP\Administrator.
IntegrityLevel: High
ProcessGuid : {A3C21F08-1C3E-65F2-FF00-000000009401}
ProcessId   : 7024
Parent      : mimikatz.exe PID 4988

------------------------------------------
STEP 6 — Stage2 Download and Execute (Event ID 1: ProcessCreate)
------------------------------------------
The Administrator powershell session spawns a second powershell
with an IWR (Invoke-WebRequest) one-liner that:
  1. Downloads stage2.exe from http://10.0.0.10/stage2.exe
  2. Saves it to C:\Windows\Temp\ under its SHA256 hash as filename
  3. Immediately executes it with Start-Process
RuleName T1059.001 (PowerShell) fired.
ProcessGuid : {A3C21F08-1D5F-65F2-1101-000000009401}
ProcessId   : 8812
Parent      : powershell.exe PID 7024 (CORP\Administrator session)

==========================================
FULL PROCESS CHAIN (GUID → GUID)
==========================================
explorer.exe        {0D3B}  PID 3120
  └─ IDM.exe        {1A04}  PID 5736   initial access + C2 beacon + file drop
       └─ cmd.exe   {1B11}  PID 6012   reverse shell, registry UAC poison
            └─ fodhelper.exe {1B12} PID 6204   UAC bypass, High integrity
                 └─ mimikatz.exe {1C22} PID 4988   credential dump lsass
                      ├─ [EVENT 10 → lsass {0A11} PID 688]
                      └─ powershell.exe {1C3E} PID 7024   PtH as Administrator
                           └─ powershell.exe {1D5F} PID 8812   IWR stage2
==========================================