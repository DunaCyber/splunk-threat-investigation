# Threat Scenario Investigation — Splunk Walkthrough

## Executive summary

This investigation reviewed Windows endpoint and security telemetry from a TryHackMe lab to assess a suspected collection-and-exfiltration sequence.

- Remote-management activity involving `THM-MSMITH` was followed by directory, account, administrator-group, and share enumeration.
- Remote PowerShell activity originating from `THM-SREYES` and network-share access recorded on `DC-01` occurred in the same general period.
- PowerShell commands on `THM-SREYES` attempted to stage marketing and NeuralNexus project files.
- A `Compress-Archive` command attempted to package the staged content as `review-cache.zip`.
- `curl.exe` was launched with an explicit command to upload that archive to `45.147.230.131:8443`.
- The evidence supports suspicious collection and attempted transfer behavior, but does not confirm that all copies or archive creation succeeded, that the upload completed, or that all observed activity had one operator.

## 1. Lab environment and data sources
The investigation used the TryHackMe lab environment and Splunk to search collected Windows telemetry.

Tools and sources:

- **Splunk:** searched, filtered, sorted, and correlated event records.
- **Sysmon:** reviewed process creation, network connections, and selected process/file activity.
- **PowerShell Script Block Logging:** examined PowerShell commands recorded in script block events.
- **Windows Security logs:** reviewed successful logons and network-share access, including Event IDs 4624, 5140, and 5145.

Relevant systems and identities:

| System / identity | Role in the investigation |
|---|---|
| `THM-SREYES` | Workstation where the collection script and upload command were observed |
| `THM-MSMITH` | Remote workstation containing the marketing release directory |
| `DC-01` | Domain controller / system recording access to `ReleaseStaging` |
| `TRYHATME\s.reyes` | User associated with the PowerShell collection and upload sequence |
| `TRYHATME\svc-studioops` | Service account associated with remote-management, reconnaissance, and share-access events |


### Stage 1 — Remote access and marketing directory discovery

**Timestamp:** `2026-09-10 15:03:37`  
**User:** `TRYHATME\svc-studioops`  
**Asset:** `THM-MSMITH`  
**Tactics:** Discovery; Lateral Movement  
**Techniques:** T1083 — File and Directory Discovery; T1021.006 — Windows Remote Management

**What happened**

A Windows Remote Management host process, `wsmprovhost.exe`, launched `cmd.exe` to list the contents of:

`C:\StudioMarketing\approved-release`

This indicates remote command execution and discovery of marketing release files. The command alone does not prove malicious intent, but it becomes more suspicious when considered alongside the later collection and upload activity.

**Evidence / indicators**

- Process: `C:\Windows\System32\wsmprovhost.exe`
- Child process: `C:\Windows\System32\cmd.exe`
- Command line: `cmd.exe /c dir C:\StudioMarketing\approved-release`
- Target directory: `C:\StudioMarketing\approved-release`
- Parent process ID: `5688` (`wsmprovhost.exe`)
- Child process ID: `6432` (`cmd.exe`)
- Evidence source: Sysmon Event ID 1

**Analyst interpretation**

The parent process is consistent with a WinRM remote session. The `dir` command indicates file and directory discovery on the remote host. This is an investigative lead, not proof that files were accessed or copied.

### Stage 2 — Account, administrator-group, and share discovery

**Timestamp:** `2026-09-10 16:03:38`  
**User:** `TRYHATME\svc-studioops`  
**Asset:** `THM-MSMITH`  
**Tactic:** Discovery  
**Techniques:** T1087.001 — Account Discovery: Local Account; T1069.001 — Permission Groups Discovery: Local Groups; T1135 — Network Share Discovery

**What happened**

A remote-management process launched three Windows commands:

- `net.exe user`
- `net.exe localgroup Administrators`
- `net.exe share`

These commands enumerate local user accounts, membership of the local Administrators group, and available network shares. Together, they are consistent with reconnaissance to identify accounts, privileges, and accessible resources.

**Evidence / indicators**

- Parent process: `C:\Windows\System32\wsmprovhost.exe`
- Process: `C:\Windows\System32\net.exe`
- Parent process ID: `5688`
- Child process IDs: `9636`, `2632`, `4872`
- Evidence source: Sysmon Event ID 1

**Analyst interpretation**

The commands provide information that could help an operator identify privileged accounts and resources for further access. Their execution under a service account and in a remote-management context warrants review. The commands alone do not establish that the account was compromised.

### Stage 3 — Remote PowerShell and release-share access

**Time window:** Remote PowerShell activity began at approximately `2026-09-10 16:24:50`; related share-access and remote-management records were observed around `16:27:02`. These are separate events, not one continuous action.  
**Users:** `TRYHATME\s.reyes`; `TRYHATME\svc-studioops`  
**Assets:** `THM-SREYES`; `THM-MSMITH`; `DC-01`  
**Tactic:** Lateral Movement  
**Technique:** T1021.006 — Windows Remote Management (applies to the remote PowerShell and `wsmprovhost.exe` activity)

**What happened**

PowerShell activity on `THM-SREYES` used a remote PowerShell session to connect to `THM-MSMITH`.

Around the same period, Windows Security logs on `DC-01` recorded a successful network logon by `TRYHATME\svc-studioops` from `10.60.10.22` and access to the `ReleaseStaging` share. A separate `wsmprovhost.exe` process was also observed on `THM-MSMITH` under the service account.

Together, these events warrant investigation for possible lateral movement and access to release materials. Event ID 5140 indicates share access, not share discovery; the separate `net.exe share` command in Stage 2 is the evidence supporting Network Share Discovery. The available logs do not establish that both accounts were controlled by the same actor.

**Evidence / indicators**

- Source host: `THM-SREYES`
- Remote host: `THM-MSMITH`
- Source IP associated with share access: `10.60.10.22`
- Destination port: TCP `5985` (commonly used by WinRM)
- DNS query: `thm-msmith`
- Resolved address: `10.60.10.22`
- Network share: `\\DC-01\ReleaseStaging`
- Share path: `C:\ReleaseStaging`
- Service account: `TRYHATME\svc-studioops`
- `DC-01` logon ID: `0x1366840`
- Event IDs: Windows Security `4624`, `5140`; Sysmon `1`; PowerShell `4104`

**Additional correlation**

The source IP recorded for the `svc-studioops` share access on `DC-01` (`10.60.10.22`) matches the address resolved for `THM-MSMITH`. This suggests that the share-access event originated from `THM-MSMITH`, linking the host involved in the remote-management activity with the source recorded in the domain-controller logs. This is an IP-based correlation and does not prove that the same operator conducted all observed activity.

**Analyst interpretation**

The events provide evidence of remote PowerShell activity and network-share access in the same general time window. Event ID 4624 supports a successful logon; Event ID 5140 records network-share access. Neither event alone proves which files were read or copied. The distinct user identities should not be merged into one actor attribution without additional evidence. The T1021.006 mapping applies to the observed WinRM-related activity, not independently to the Windows Security share-access events (Event IDs 4624 and 5140).


**Additional remote-management event (original course Stage 7)**

At `2026-09-10 16:27:02`, Sysmon recorded `wsmprovhost.exe` under `TRYHATME\svc-studioops` on `THM-MSMITH`. This event is relevant because it occurred near the remote PowerShell and share-access activity, but it does not independently establish malicious execution or a direct link to the `s.reyes` collection and upload sequence.

- Process: `C:\Windows\System32\wsmprovhost.exe`
- Command line: `C:\Windows\system32\wsmprovhost.exe -Embedding`
- Process ID: `3968`
- Logon ID: `0x19AE544`
- SHA-256: `30C91BE613CB8BF4A882DEB2D3B77C8ABC0C41617178BA3681CFA746DFCED273`
- Evidence source: Sysmon Event ID 1

`wsmprovhost.exe` is a legitimate Windows component used to host remote-management sessions. Its presence is not inherently malicious; account, timing, parent/child process relationships, and surrounding activity provide the relevant context.

### Stage 4 — Collection and local staging

**Timestamp:** `2026-09-10 16:27:01`  
**User:** `TRYHATME\s.reyes`  
**Asset:** `THM-SREYES`, with a remote source on `THM-MSMITH`  
**Tactic:** Collection  
**Technique:** T1074.001 — Data Staged: Local Data Staging

**What happened**

PowerShell Script Block Logging recorded commands that attempted to copy files from `C:\StudioMarketing\approved-release` on `THM-MSMITH` into a local staging directory on `THM-SREYES`. The script also attempted to copy local NeuralNexus release notes into the staging area.

This behavior is consistent with collecting and consolidating potentially sensitive project and marketing materials before archive creation.

**Evidence / indicators**

- Script: `C:\Users\s.reyes\AppData\Local\NeuralNexus\review-helper.ps1`
- Remote host: `THM-MSMITH`
- Remote source directory: `C:\StudioMarketing\approved-release`
- Local source directory: `C:\StudioProjects\NeuralNexus\release-notes`
- Staging directory: `%TEMP%\review-staging\marketing`
- Staging subdirectory: `%TEMP%\review-staging\project`
- PowerShell commands: `New-PSSession`; `Copy-Item -FromSession`
- Evidence source: PowerShell Event ID 4104

**Analyst interpretation**

The script block records commands submitted for execution. They support an attempted collection and staging workflow, but script-block evidence by itself does not verify that every copy operation completed successfully or that every source file was copied. The remote directory path alone does not establish that the source was a Windows network share, so T1039 is not assigned here.

### Stage 5 — Archive creation

**Timestamp:** `2026-09-10 16:27:28`  
**User:** `TRYHATME\s.reyes`  
**Asset:** `THM-SREYES`  
**Tactic:** Collection  
**Technique:** T1560.001 — Archive Collected Data: Archive via Utility

**What happened**

PowerShell script-block telemetry recorded a `Compress-Archive` command targeting the local staging directory and specified `%TEMP%\review-cache.zip` as the output. The archive was subsequently referenced by an external upload command.

**Evidence / indicators**

- Script: `C:\Users\s.reyes\AppData\Local\NeuralNexus\review-helper.ps1`
- Command: `Compress-Archive`
- Source: `%TEMP%\review-staging\*`
- Target archive: `%TEMP%\review-cache.zip`
- Evidence source: PowerShell Event ID 4104

**Analyst interpretation**

The command indicates an attempt to package staged files into an archive. The later reference to the archive in an upload command strengthens the collection-and-transfer hypothesis. The script-block record alone should not be treated as independent proof that the archive was successfully created.

### Stage 6 — Attempted external upload

**Timestamp:** `2026-09-10 16:27:54`  
**User:** `TRYHATME\s.reyes`  
**Asset:** `THM-SREYES`  
**Tactic:** Exfiltration  
**ATT&CK mapping:** No exfiltration technique confirmed

**What happened**

Sysmon recorded `curl.exe` launching with an explicit file-upload command targeting:

`https://45.147.230.131:8443/ingest/review-cache.zip`

The process was launched by PowerShell running `review-helper.ps1` under `s.reyes`. The command is consistent with an attempted transfer of the staged archive to an external destination. Process-creation evidence does not prove that the upload succeeded. Because the available evidence does not establish successful transfer or whether the destination was a command-and-control channel or a non-C2 service, no ATT&CK exfiltration technique is assigned.

**Evidence / indicators**

- Script: `C:\Users\s.reyes\AppData\Local\NeuralNexus\review-helper.ps1`
- Process: `C:\Windows\System32\curl.exe`
- Process ID: `7060`
- Parent process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Parent process ID: `5020`
- Referenced archive: `%TEMP%\review-cache.zip`
- Destination IP: `45.147.230.131`
- Destination port: TCP `8443`
- URL: `https://45.147.230.131:8443/ingest/review-cache.zip`
- SHA-256 of `curl.exe`: `664BB48BF3E8A7D7036E4B0029FA10E1A90C2562AD9A09A885650408D00DEA1B`
- Evidence sources: Sysmon Event ID `1`; PowerShell Event ID `4104`

**Analyst interpretation**

The process command line is direct evidence that an upload command was launched with the archive path and external destination. T1041 would require evidence that the transfer used a command-and-control channel. T1048.002 could be considered only if further evidence established exfiltration over an asymmetrically encrypted, non-C2 protocol. HTTPS to a bare IP address alone does not establish those conditions. To determine whether data left the environment, additional evidence would be needed, such as a corresponding network connection and transfer response, proxy or firewall records, server-side receipt, or other telemetry confirming the transfer.


## 3. Splunk searches and search rationale

### Search 1 — Review process creation on the remote host

**Investigation question:** Which processes were created on `THM-MSMITH`, and what were their users, parent processes, and command lines?

**Documented SPL:**

```spl
index="scenario" ComputerName="THM-MSMITH" EventCode=1
| table _time User Image ParentImage ProcessId ParentProcessId CommandLine
| sort 0 _time
```

**Why this search was used**

- `index="scenario"` limits the search to the lab's scenario index.
- `ComputerName="THM-MSMITH"` focuses on the remote workstation involved in the directory discovery and service-account activity.
- `EventCode=1` selects Sysmon process-creation events.
- `table` displays the timestamp, user, executable, parent executable, process identifiers, and command line—the fields needed to reconstruct process execution and parent/child relationships.
- `sort 0 _time` sorts the returned events chronologically. The `0` requests that Splunk return all results rather than applying the default result limit for this sort operation.

**What this search was intended to establish**

Whether remote-management processes such as `wsmprovhost.exe` launched commands such as `cmd.exe` or `net.exe`, and which account and command line were associated with those processes.

**Findings associated with this part of the investigation**

The retained findings identify `wsmprovhost.exe` launching `cmd.exe /c dir C:\StudioMarketing\approved-release` at 15:03:37, followed by `net.exe` account, administrator-group, and share enumeration at 16:03:38. A further `wsmprovhost.exe` process was recorded at 16:27:02.

### Search 2 — Review PowerShell and upload-related activity

**Investigation question:** Where did the archive name `review-cache.zip` appear, and what process, user, host, or command context was recorded with it?

**Documented SPL:**

```spl
index="scenario" "review-cache.zip"
| table _time ComputerName EventCode User Image ParentImage ProcessId ParentProcessId CommandLine Message
| sort 0 _time
```

**Why this search was used**

- The archive filename is a distinctive search term linking the archive-creation and upload portions of the activity.
- Searching for the filename can locate events that mention the archive even when they come from different telemetry sources.
- The selected fields provide process context where available, including the executable, parent process, process identifiers, command line, and event message.
- `sort 0 _time` places matching events in chronological order so the archive reference can be compared with the surrounding activity.

**What this search was intended to establish**

Whether the archive filename appeared in PowerShell script-block records, process-creation events, or other collected telemetry, and whether the references supported a sequence from staging to archive creation to an upload command.

**Findings associated with this part of the investigation**

The retained findings describe a `Compress-Archive` command targeting `%TEMP%\review-staging\*` and writing `%TEMP%\review-cache.zip` at 16:27:28. At 16:27:54, `curl.exe` was launched with an upload command referencing that archive and the external URL. The available evidence does not confirm successful transfer.

### Search 3 — Review access to the ReleaseStaging share

**Investigation question:** Did Windows Security logs record access to the `ReleaseStaging` network share, and which account and source address were associated with it?

**Documented SPL:**

```spl
index="scenario" (EventCode=5140 OR EventCode=5145)
| search "DC-01" OR "ReleaseStaging"
| table _time EventCode ComputerName User IpAddress ShareName RelativeTargetName Message
| sort 0 _time
```

**Why this search was used**

- Event ID `5140` records when a network share was accessed.
- Event ID `5145` records a detailed network-share access check, which can provide additional information about the requested access and target.
- Searching for `DC-01` or `ReleaseStaging` narrows the results to the share and system relevant to the investigation.
- The table includes the user, source IP, share name, relative target name, and message so the analyst can assess the recorded access context.
- Chronological sorting helps align share activity with the remote PowerShell and collection timeline. Field names such as `IpAddress`, `ShareName`, and `RelativeTargetName` depend on the Splunk field extractions, Windows event format, and installed add-ons. If a field is empty, inspect the raw event and available extracted fields rather than assuming the event contains no relevant value.

**What this search was intended to establish**

Whether `TRYHATME\svc-studioops` accessed `\\DC-01\ReleaseStaging`, and whether the records contained details about a specific target within the share.

**Findings associated with this part of the investigation**

The retained findings state that `DC-01` recorded a successful network logon by `TRYHATME\svc-studioops` from `10.60.10.22` and access to `ReleaseStaging` around 16:27:02. Share-access evidence alone does not establish that particular files were copied.

### Search 4 — Correlate service-account activity

**Investigation question:** What logon, share-access, and privilege-related events were associated with `svc-studioops` across the relevant systems?

**Documented SPL:**

```spl
index="scenario" "svc-studioops"
(EventCode=4624 OR EventCode=4625 OR EventCode=5140 OR EventCode=5145 OR EventCode=4672)
| table _time ComputerName EventCode User Message
| sort 0 _time
```

**Why this search was used**

- Searching for `svc-studioops` focuses the review on activity associated with the service account.
- Event ID `4624` records successful logons; `4625` records failed logons.
- Event IDs `5140` and `5145` relate to network-share access and detailed share-access checks.
- Event ID `4672` records special privileges assigned to a new logon.
- Displaying the host, event ID, user, and message helps compare account activity across systems and event types.
- Chronological sorting helps identify whether logon and share-access activity occurred near the remote-management and collection sequence.

**What this search was intended to establish**

Whether the service account's authentication and share-access activity aligned with the observed remote-management activity, and whether additional logon or privilege events warranted follow-up.

**Analytical limitation**

The presence of the same account name across events does not, by itself, prove that one actor controlled every session or performed every action. Compare host, source address, logon ID, timestamps, and process context before drawing that conclusion.

## 4. Consolidated timeline
All times below are from the retained course findings and are presented as recorded.

| Date and time | Host / system | Observed activity | Interpretation |
|---|---|---|---|
| 2026-09-10 15:03:37 | `THM-MSMITH` | `wsmprovhost.exe` launched `cmd.exe` to list the marketing release directory | Remote command execution and file/directory discovery |
| 2026-09-10 16:03:38 | `THM-MSMITH` | `net.exe user`, `net.exe localgroup Administrators`, and `net.exe share` | Account, group, and share enumeration |
| 2026-09-10 16:24:50 | `THM-SREYES` → `THM-MSMITH` | Remote PowerShell session activity began | Remote-management activity; full session details are not established by the retained notes |
| 2026-09-10 16:27:01 | `THM-SREYES` | PowerShell commands attempted to copy marketing and NeuralNexus files to staging directories | Potential collection and local staging |
| 2026-09-10 16:27:02 | `THM-MSMITH`; `DC-01` | `wsmprovhost.exe` under `svc-studioops`; successful logon/share-access records associated with `ReleaseStaging` | Additional remote-management and share-access activity; relationship to the `s.reyes` sequence is unconfirmed |
| 2026-09-10 16:27:28 | `THM-SREYES` | `Compress-Archive` referenced the staging directory and `review-cache.zip` | Archive creation attempted |
| 2026-09-10 16:27:54 | `THM-SREYES` | `curl.exe` launched with an upload command to `45.147.230.131:8443` | Attempted external transfer; success unconfirmed |

**Timeline note:** The event originally labeled Stage 7 in the course report is incorporated into Stage 3 above and placed here by its timestamp. The original seven course stages remain identifiable in the narrative.

## 5. MITRE ATT&CK mapping
Mappings below describe observed behavior. They do not independently establish malicious intent or prove that every action succeeded.

| Observed behavior | ATT&CK technique | Rationale and confidence |
|---|---|---|
| Remote PowerShell / WinRM activity | T1021.006 — Windows Remote Management | `wsmprovhost.exe` and remote PowerShell activity were observed. This supports use of WinRM; the process itself is a legitimate Windows component. |
| Listing a directory | T1083 — File and Directory Discovery | `dir C:\StudioMarketing\approved-release` enumerated a target directory. |
| User enumeration | T1087.001 — Account Discovery: Local Account | `net.exe user` queried user accounts. |
| Local administrator-group enumeration | T1069.001 — Permission Groups Discovery: Local Groups | `net.exe localgroup Administrators` queried local group membership. |
| Share enumeration | T1135 — Network Share Discovery | `net.exe share` enumerated available shares. |
| Local data staging | T1074.001 — Data Staged: Local Data Staging | Commands attempted to consolidate files in local staging directories. |
| Archive creation | T1560.001 — Archive Collected Data: Archive via Utility | PowerShell used `Compress-Archive` to package staged content. |
| Attempted outbound transfer | No confirmed ATT&CK exfiltration technique | `curl.exe` was launched with an upload command. T1041 is not confirmed because the destination has not been established as a C2 channel; HTTPS alone is insufficient to assign T1041 or another exfiltration technique. |

## 6. Indicators and evidence summary
| Indicator | Context |
|---|---|
| `THM-SREYES` | Host associated with the collection script and upload command |
| `THM-MSMITH` | Host containing the marketing release directory and remote-management activity |
| `DC-01` | System recording `ReleaseStaging` share access |
| `TRYHATME\s.reyes` | User associated with the PowerShell collection and upload sequence |
| `TRYHATME\svc-studioops` | Service account associated with remote-management, reconnaissance, and share-access events |
| `C:\Users\s.reyes\AppData\Local\NeuralNexus\review-helper.ps1` | PowerShell script associated with collection, archive, and upload activity |
| `%TEMP%\review-staging\marketing` | Marketing staging directory |
| `%TEMP%\review-staging\project` | Project staging directory |
| `%TEMP%\review-cache.zip` | Archive referenced by the archive and upload commands |
| `45.147.230.131:8443` | External destination in the `curl.exe` upload command |
| `https://45.147.230.131:8443/ingest/review-cache.zip` | Full destination URL in the process command |
| `664BB48BF3E8A7D7036E4B0029FA10E1A90C2562AD9A09A885650408D00DEA1B` | SHA-256 reported for `curl.exe` |
| `30C91BE613CB8BF4A882DEB2D3B77C8ABC0C41617178BA3681CFA746DFCED273` | SHA-256 reported for `wsmprovhost.exe` |

## 7. Assessment and limitations
### Assessment

The retained evidence supports a sequence involving:

1. Remote-management activity and discovery of a marketing release directory.
2. Enumeration of local accounts, administrator-group membership, and network shares.
3. Remote PowerShell activity and access to the `ReleaseStaging` share.
4. Commands attempting to collect marketing and NeuralNexus files into local staging directories.
5. A command attempting to package staged files into `review-cache.zip`.
6. A `curl.exe` process launched with an explicit command to upload the archive to an external destination.

This sequence is consistent with a possible collection-and-exfiltration operation. The evidence is strongest for the execution of discovery commands and the launch of the archive and upload commands. It is less conclusive about whether the file-copy and archive operations completed, whether the upload succeeded, and whether the external destination was controlled by an adversary.

### Limitations

- The original TryHackMe SIEM links and screenshots are unavailable. Event field extraction may also differ between Splunk configurations and Windows event sources; the SPL examples should be adapted to the fields available in a given environment.
- The four SPL searches in this document are representative searches preserved in the investigation notes, not a verified export of the full original Splunk search history.
- No exact result counts are claimed.
- Process-creation and script-block events show commands or scripts being launched or submitted; they do not always prove successful completion.
- Share-access events do not, on their own, prove that specific files were copied.
- The upload command does not prove that the remote server received the archive.
- The available evidence does not conclusively attribute all activity to one actor or establish that `s.reyes` and `svc-studioops` were controlled by the same person.

### Additional evidence that would strengthen the assessment

If the relevant telemetry were available, useful follow-up evidence would include:

- Sysmon network-connection records around the upload attempt, including Event ID 3 where collected.
- Proxy, firewall, DNS, or network-flow logs for `45.147.230.131:8443`.
- Server-side or receiver logs showing whether `review-cache.zip` was received.
- File-system telemetry confirming creation, size, and hash of `review-cache.zip`.
- Detailed Event ID 5145 records identifying the requested share-relative paths and access types.
- Logon IDs, source addresses, and process relationships to clarify whether the `svc-studioops` and `s.reyes` activity was connected.

## 8. Recommended incident response actions
The following are **recommended actions for a real incident**, not actions performed in the TryHackMe lab. They should be carried out under the organization's incident-response procedures, with appropriate authorization and evidence-preservation requirements.

1. **Preserve evidence first.** Secure relevant endpoint, PowerShell, Sysmon, Windows Security, DNS, proxy, and firewall logs. Record timestamps and hashes, and preserve forensic copies before making changes that could destroy volatile or on-disk evidence.
2. **Contain the suspected endpoint.** If the activity is validated as unauthorized, isolate `THM-SREYES` from the network in accordance with the incident-response plan while preserving management and forensic access where needed.
3. **Review and secure the service account.** Validate the legitimate use of `TRYHATME\svc-studioops`, review its logons and privileges, and consider disabling it or rotating its credentials after coordinating with system owners to avoid disrupting critical services.
4. **Investigate the external destination.** Review network telemetry for connections to `45.147.230.131:8443`. If the destination is confirmed malicious or unauthorized, block it through approved network controls.
5. **Hunt for related artifacts.** Search other endpoints for `review-helper.ps1`, `review-cache.zip`, the staging paths, the destination IP, and related process command lines or hashes.
6. **Validate collection and transfer.** Check file-system evidence, archive metadata, network-flow/proxy records, and receiver-side logs to determine whether files were copied, the archive was created, and any upload completed.
7. **Scope remote access.** Correlate WinRM sessions, source addresses, logon IDs, parent/child process activity, and account authentication across affected systems to determine the scope and attribution.

## 9. Portfolio note
This project documents a defensive investigation of Windows endpoint and network-share telemetry using Splunk. It demonstrates event filtering, process lineage review, PowerShell activity analysis, account and share-access correlation, timeline reconstruction, ATT&CK mapping, and evidence-based assessment.

The project intentionally distinguishes observed activity from analyst interpretation and confirmed outcomes. No screenshots or SIEM links are included because the lab environment is no longer accessible and those artifacts were not retained.
