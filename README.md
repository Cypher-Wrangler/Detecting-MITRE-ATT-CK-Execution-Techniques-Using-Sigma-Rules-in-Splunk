# Detecting-MITRE-ATT-CK-Execution-Techniques-Using-Sigma-Rules-in-Splunk
# Overview
Creating Sigma rules to be Operationalised in splunk to detect encoded Powershell execution, a common adversary technique used to obfuscate malicious commands
during the Execution phase of an attack. This project maps Sigma detection logic to Splunk SPL, aligns detection with MITRE ATT&CK, and validates them using real Windows
process-creation telemetry.

# Objective
- Detect PowerShell encoded commands (-enc, -EncodedCommand)
- Translate Sigma rules to Splunk SPL
- Aligns detections with MITRE ATT&CK Execution (TA0002)
- Validate detection using real Windows logs

Step 1
- SigmaHQ's GitHub and select the rules directory/folder
  
