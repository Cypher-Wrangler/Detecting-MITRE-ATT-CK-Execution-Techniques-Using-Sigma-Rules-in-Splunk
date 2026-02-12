# Detecting-MITRE-ATT-CK-Execution-Techniques-Using-Sigma-Rules-in-Splunk

## Overview
Creating Sigma rules to be Operationalised in splunk to detect encoded Powershell execution, a common adversary technique used to obfuscate malicious commands
during the Execution phase of an attack. This project maps Sigma detection logic to Splunk SPL, aligns detection with MITRE ATT&CK, and validates them using real Windows
process-creation telemetry.

## Objective
- Detect PowerShell encoded commands (-enc, -EncodedCommand)
- Translate Sigma rules to Splunk SPL
- Aligns detections with MITRE ATT&CK Execution (TA0002)
- Validate detection using real Windows logs

## MITRE ATT&CK Mapping
Tactic: Execution
Technique: PowerShell
ID: T1059.001

Step 1
- SigmaHQ's GitHub and select the rules directory/folder , interested in process-creation Event ID =1 for sysmon or windows Event ID = 4688
- Detection logic
- 
```yaml
title: Potential Encoded PowerShell Command Execution - Proccess Creation
id: 784c3c4b-ab8f-4d63-8c16-7c2362ea27c9
status: test
description: Detects PowerShell execution using encoded command flags
author: Kennedy Kamau
modified: 2026-02-09
references:
    - https://o365blog.com/aadinternals/
tags:
    - attack.execution
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith:
              - '\powershell.exe'
        - OriginalFileName:
              - '\PowerShell.Exe'
    selection_cli:
        CommandLine|contains:
            - '-enc '
            - '-encodedcommand'
            - '-e'
    selection_evtid:
           - EventID: 1
    condition: all of selection_*
falsepositives:
    - Legitimate use of the library for administrative activity
level: high

```
# Step using sigconverter to translate too Splunk SPL
```spl
Image="*\\powershell.exe" OR OriginalFileName="\\PowerShell.Exe" CommandLine IN ("*-enc *", "*-encodedcommand*", "*-e*") EventID=1
```

# Splunk 
SPL detected one PowerShell encoded event
<img width="2227" height="1336" alt="image" src="https://github.com/user-attachments/assets/92ae1aee-c88c-4d62-92a1-0b0fa0944265" />

## Alert Operationalization (Enterprise)
- To detect any future encoded commands being run in the environmnet, implement alerting:
  ```spl
  Image="*\\powershell.exe" OR OriginalFileName="\\PowerShell.Exe" CommandLine IN ("*-enc *", "*-encodedcommand*", "*-e*") EventID=1 | table _time, host, user, ParentImage, Image, CommandLine | sort - _time

The detection was operationalised as a scheduled alert in Splunk Enterprise.

**Alert Name:** Encoded PowerShell Execution Detected
**Schedule:** Every 5 minutes
**Trigger Condition:** Number of results > 0
**Severity:** Medium

<img width="804" height="994" alt="Screenshot 2026-02-10 143803" src="https://github.com/user-attachments/assets/b128a86a-57db-4b95-9102-3c23067e5072" />

### The alert provides the following fields to support rapid triage:
 - Timestamp
 - User account
 - Parent process
 - Full commmand line

### Analyst Response Workflow
- Review the encoded PowerShell commmand line
- Decode the Base64 payload to determine the intent
- Identify the parent process
- Scope the execution across assets
- Escalate to incident response if malicious behavior is confirmed.
