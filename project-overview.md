# Windows Threat Investigation with Splunk

A defensive security investigation of Windows endpoint and authentication telemetry from a TryHackMe lab. The project documents how I used Splunk to examine remote-management activity, Windows process execution, PowerShell commands, network-share access, file staging, archive creation, and an attempted outbound upload.

## Project objective

Reconstruct a suspected collection-and-exfiltration sequence from available Windows telemetry, explain the investigative searches, and distinguish observed evidence from conclusions that the logs do not support.

## Key investigation findings

- Observed WinRM-related activity involving `THM-MSMITH`, including directory and system reconnaissance.
- Identified remote PowerShell activity originating from `THM-SREYES` and separate network-share access records on `DC-01`.
- Reviewed PowerShell commands that attempted to stage marketing and NeuralNexus project files.
- Identified a `Compress-Archive` command referencing `%TEMP%\review-cache.zip`.
- Identified a `curl.exe` process launched with an explicit upload command to `45.147.230.131:8443`.
- Assessed the activity as consistent with possible collection and attempted exfiltration, while noting that successful copying, archive creation, upload completion, and common actor attribution were not conclusively established.

## Skills demonstrated

- Splunk Search Processing Language (SPL)
- Windows event-log analysis
- Sysmon process and parent-child relationship review
- PowerShell Script Block Logging analysis
- Windows authentication and network-share event correlation
- Timeline reconstruction
- MITRE ATT&CK behavior mapping
- Evidence-based incident assessment and response recommendations

## Tools and telemetry

- **Splunk** — searching, filtering, sorting, and correlating event records
- **Sysmon** — process creation and related endpoint telemetry
- **PowerShell Script Block Logging** — Event ID 4104
- **Windows Security auditing** — including Event IDs 4624, 5140, and 5145
- **TryHackMe** — lab environment

## Repository contents

| File | Description |
|---|---|
| [`investigation-walkthrough.md`](02-investigation-walkthrough.md) | Detailed investigation stages, documented SPL searches, query rationale, timeline, indicators, ATT&CK mapping, limitations, and recommended response actions |

## Evidence and methodology note


The analysis distinguishes between:
- **Observed:** events or commands recorded in the retained investigation findings.
- **Attempted:** actions for which command execution was observed but successful completion was not independently confirmed.
- **Inferred:** an interpretation supported by multiple observations but not conclusively proven.

## Conclusion

The available evidence supports a suspicious sequence of remote administration, reconnaissance, attempted file collection and staging, archive creation, and an attempted external upload. Further endpoint, network, and receiver-side evidence would be required to confirm whether data was successfully transferred and to determine whether the separate account and host activity was conducted by the same actor.

---

*Educational portfolio project based on a TryHackMe lab. The response actions in the walkthrough are recommendations for a hypothetical real-world incident; they were not performed in the lab.*
