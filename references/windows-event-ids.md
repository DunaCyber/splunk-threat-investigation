# Windows Event ID Reference

These are general descriptions of Windows Security event IDs that can be useful during investigations. Their presence in a lab does not mean every event was relevant to, or confirmed by, this investigation.

| Event ID | General meaning | Investigative use |
|---|---|---|
| 4624 | A logon succeeded. | Review account, logon type, source, and host context. |
| 4625 | A logon failed. | Look for patterns of failed authentication. |
| 4672 | Special privileges were assigned to a new logon. | Review whether the account and logon context are expected. |
| 5140 | A network share was accessed. | Identify share access and examine account and source. |
| 5145 | A detailed network-share access check occurred. | Review requested access, share path, and context. |

## Cautions
- An event ID is not a verdict. Interpret full event fields and surrounding activity.
- A successful logon is not automatically suspicious.
- A failed logon does not automatically indicate compromise.
- Share-access events do not alone prove data was copied.
- Confirm event source and logging configuration before drawing conclusions.
