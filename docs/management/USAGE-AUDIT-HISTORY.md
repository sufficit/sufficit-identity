# Administrative profile audit history

Administrative profile updates record `user_profile_updated`, the operator,
account ID, UTC timestamp, authorization outcome and correlation ID. Successful
changes also populate `beforeJson` and `afterJson` in the existing audit record.
These are JSON strings containing **only changed fields**, from this allowlist:
`userName`, `email`, `emailConfirmed`, `phoneNumber`, `phoneNumberConfirmed`.
Confirmation resets caused by changing an address/phone are included. A cleared
value is represented by JSON `null`; an absent key means that field did not change.

The snapshots and the profile update commit in the same database transaction.
No-op updates retain `user_profile_unchanged` and null snapshots. Failed or
rolled-back updates never produce successful change snapshots. Passwords,
hashes, security stamps, tokens and claims are not captured.

This covers the administrative profile-update service (`PUT /api/users/{id}/profile`),
not historical changes or every provisioning surface. Old events with null
snapshots remain null. It does not change login or synchronize usernames with e-mail.
No schema migration is required: the snapshot columns already exist.

## Searching retained history

`POST /api/audit/search` requires the existing management authentication policy
and `identity.audit.read`. Use the same authentication as other management APIs.
Supply JSON in the request body:

```json
{
  "resourceType": "user",
  "resourceId": "example-user-id",
  "fromUtc": "2026-11-05T00:00:00-03:00",
  "toUtc": "2026-11-06T00:00:00-03:00",
  "limit": 100,
  "cursor": null
}
```

All filters are optional. Resource filters use equality, with the existing
provider/database comparison semantics, not substring search. Time offsets are
normalized to UTC. The interval includes `fromUtc` and excludes `toUtc`.
The limit defaults to 100 and is clamped to 1–250.

The response is `{ "items": [...], "nextCursor": "..." }`. Pass `nextCursor`
back as `cursor`, retaining the filters, until it is null. Ordering is descending
by timestamp and then audit ID. A cursor is a position, not an access grant;
every page checks authorization again. Newer concurrent inserts do not shift
older page boundaries. This is not a transactionally frozen export: retention
can remove rows during traversal. Restart the search to include new events.

Invalid cursors, oversized filters and empty/reversed time intervals return
HTTP 400. Both search and the original `GET /api/audit?limit=100` send
`Cache-Control: no-store`. The GET endpoint retains its array response and limit
behavior; existing consumers and the embedded audit list remain compatible.
Consumers implementing `IManagementAuditService` must implement `SearchAsync`.

## Security and retention

The retained values are personal data, available only to audit-authorized
operators. Do not publish or forward the response to ordinary application logs.
The existing `Sufficit:Identity:Management:AuditRetentionDays` setting applies
(default 15 days; explicit deployment overrides remain in effect). This change
neither extends retention nor reconstructs deleted events.

The design review found no conflict in the consulted RFC requirements for this
administrative API. It does not modify OAuth/OIDC or SCIM protocol behavior:

- [RFC 9110 §17.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-17.8)
  treats logs as confidential and calls for removing personal information when
  no longer operationally necessary. Access controls, changed-field minimization
  and the existing retention worker apply here.
- [RFC 9110 §17.9](https://www.rfc-editor.org/rfc/rfc9110.html#section-17.9)
  warns against sensitive information in URLs. Search filters travel in a POST
  body; there is no new e-mail search parameter in a URI.
- [RFC 9700 §4.9.3](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.9.3)
  requires protection of access tokens. The snapshot allowlist excludes all
  credentials and the search response contains no bearer tokens.

Evidence: `ManagementAuditSearchTests`,
`UserManagementControllerTests.ProfileAudit` and the existing retention tests.
