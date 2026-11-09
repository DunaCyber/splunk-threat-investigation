# Investigation Findings

## Executive summary
The available lab telemetry showed suspicious PowerShell and remote-session activity, network-share access, creation of a compressed archive, and a `curl.exe` command referencing an external destination.

Together, these observations are consistent with possible file collection and an attempted outbound transfer. The reviewed evidence did not independently establish that the external transfer completed successfully.

## Observed activity

### PowerShell and remote-session activity
The investigation identified PowerShell activity and `wsmprovhost.exe`, a process associated with hosting remote PowerShell sessions through Windows Remote Management (WinRM).

**Supports:** Remote PowerShell session activity was present in the available telemetry.

**Does not establish by itself:** Whether the session was malicious, how the activity began, or whether every command succeeded.

### Account and host activity
The lab activity involved `s.reyes`, `THM-SREYES`, `THM-MSMITH`, and `svc-studioops`.

The investigation considered multiple user, service-account, and host identifiers. The complete authentication path and legitimacy of every account action require supporting event details.

### Network-share access
Network-share activity was reviewed. Windows event IDs 5140 (network share accessed) and 5145 (detailed file-share access check) may be relevant to this type of investigation.

**Limitation:** A share-access event does not, by itself, prove that files were successfully copied or collected.

### Archive creation
The investigation identified creation of `review-cache.zip`.

**Supports:** A compressed archive was created in the lab scenario.

**Unresolved:** Its exact contents and whether all relevant files were included, unless confirmed by additional evidence.

### External transfer command
The investigation identified a `curl.exe` command referencing `45.147.230.131:8443`.

**Supports:** A command referencing an external destination was recorded.

**Does not prove:** That a connection succeeded, data was transmitted, or the receiving system obtained the archive. Confirmation would require additional network or destination-side evidence.

## Assessment
The sequence raises concern for possible remote access, file staging, and attempted data exfiltration in the simulated environment.

The defensible conclusion is that the telemetry showed activity **consistent with attempted collection and external transfer**. Successful exfiltration was not confirmed by the evidence reviewed.

## Evidence versus interpretation

| Item | Evidence-based statement | Avoid claiming |
|---|---|---|
| PowerShell | Commands were recorded in available logs. | Every command succeeded. |
| `wsmprovhost.exe` | A process associated with remote PowerShell sessions was present. | Its presence alone proves malicious access. |
| Share events | Network-share access activity was recorded. | Files were definitely copied. |
| `review-cache.zip` | Archive creation was identified. | Its contents are known without further evidence. |
| `curl.exe` | A command referencing an external destination was recorded. | The upload completed successfully. |

## Useful follow-up evidence
- Network telemetry showing whether a connection to the destination succeeded.
- Proxy, firewall, or packet-capture records showing whether data was transmitted.
- File-system evidence identifying archive contents and handling.
- Destination-side logs confirming receipt.
- Authentication and process telemetry clarifying the initial access path.

## Lessons learned
- Correlating events across hosts provides more context than reviewing one event alone.
- Process names and command lines need context; legitimate utilities can be used for suspicious purposes.
- Logs often show attempted actions, not necessarily successful outcomes.
- Reports should distinguish observed evidence, interpretation, and unresolved questions.
