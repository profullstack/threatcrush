# Incident evidence and resolution

Incident details show bounded, linked detection evidence from the same organization and server. The incident authorization check runs before loading linked detections. Arbitrary raw metadata is not returned.

The remote address, target account, logging account, PID, journal locator and recorded command are distinct fields. Missing fields are explicitly unknown. A root-owned sshd logging process is not proof that a remote user logged in as root. A `[preauth]` record does not establish successful authentication or command execution.

New daemon collection retains boot ID, journal cursor, PID and audit identifiers. A missing SSH peer address can be recovered from a previous root-owned sshd record with the same boot and PID within 120 seconds. The correlation basis is retained. It cannot recover evidence that the deployed collector never uploaded. This is bounded process correlation, not proof of a human identity; PID reuse remains a limitation.

The page supplies investigation and remediation guidance. It does not execute commands, block addresses or automatically remediate a host. Inspect the original logs, verify connection outcomes, and act only on established evidence.

## Closing an incident

Both REST PATCH and MCP `incidents_update` require the following when transitioning to resolved:

```json
{
  "status": "resolved",
  "resolution": {
    "reason": "Connection rejected before authentication; no successful login found",
    "action": "No credential change needed after reviewing this connection",
    "verification": "Reviewed original sshd records for the same connection and confirmed rejection"
  }
}
```

This example is a shape, not a finding about any particular incident. Record only actions and verification actually performed. The server sets the user or agent-key identity and recording time; caller-supplied actor fields are ignored. Resolution metadata and status are written in the same incident update. This records an operator's assessment, not independent proof that a fix ran.

Apply `20261030230000_incident_resolution.sql` before deploying the web update. Existing resolved incidents remain without resolution evidence and display that limitation. Reopening preserves the last closure record; closing again replaces it with the latest resolution. This is not a complete immutable history of every status/assignment mutation. A later audit-history feature should store those transitions separately.

API/MCP clients that previously sent only `status=resolved` must send resolution details. Acknowledge, reopen, assignment and notes remain available. After merge, release and update the daemon separately to collect the additional journal provenance; the web release alone cannot improve future host collection.
