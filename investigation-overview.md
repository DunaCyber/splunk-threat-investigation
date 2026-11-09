# Investigation Overview

## Objective
Investigate suspicious activity in a simulated Windows environment and use available event data to understand what happened, which systems and accounts were involved, and whether the evidence supports a potential data-exfiltration concern.

## Scenario context
The lab involved activity associated with `s.reyes` on `THM-SREYES`, with remote activity involving `THM-MSMITH` and the service account `svc-studioops`. The investigation included PowerShell activity, remote-session processes, network-share access, archive creation, and a `curl.exe` command referencing `45.147.230.131:8443`.

These identifiers are part of the simulated lab scenario.

## Questions
1. What activity occurred on the investigated endpoint?
2. Which processes and commands were involved?
3. Was there evidence of remote access or activity on another host?
4. Were network shares accessed?
5. Was data staged or compressed?
6. Was an external transfer attempted, and can the evidence confirm success?

## Data sources and tools
- Splunk searches over the lab's collected telemetry
- Sysmon events
- Windows Event Logs
- PowerShell-related event data

Record the exact index, sourcetype, host filters, and event sources you used in `../splunk/searches.md`. Do not guess these values.

## Approach
1. Establish relevant hosts, users, time range, and data sources.
2. Search for process and PowerShell activity.
3. Review authentication and remote-session activity.
4. Examine network-share access and file-related events.
5. Correlate events by time, host, user, process, or other available identifiers.
6. Build a timeline from the evidence.
7. Document findings, confidence, and unresolved questions.

## Limitations
A command appearing in logs demonstrates that the command was recorded; it does not automatically prove that every operation it requested succeeded.
