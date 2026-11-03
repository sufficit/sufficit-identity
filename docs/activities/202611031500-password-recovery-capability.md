# Capability for the password recovery link (03/11/2026)

A support operator holding the `manager` role was refused the "send password
recovery link" action (`capability_not_granted` for `identity.users.reset`).

Granting `identity.users.reset` would have given far more than that action: it
also sets a password chosen by the operator, removes external logins and issues
system-user credentials, and the deployment has no protected principals
configured. NIST SP 800-63B-4 §3.1.1.1 also requires a password to be chosen by
the subscriber or assigned randomly.

## Change

- New capability `identity.users.recovery`: only `POST /api/users/{id}/password-recovery`.
  The link goes to the confirmed mailbox and the owner chooses the password.
- `identity.users.reset` still satisfies the action, so no holder loses it. The
  audit row names the capability actually used; a refusal names the narrow one,
  unless the operator holds `reset` and only lacks a second factor.
- The capability goes through the protected-principal policy like `reset`.
- `ManagementUserActions` gained `CanRequestPasswordRecovery`,
  `RequestPasswordRecoveryRequiresMfa` and `RequestPasswordRecoveryReasonCode`.

## Deployment

`RoleCapabilities.manager` gains `identity.users.recovery` in
`appsettings.Production.json` on each node. It is not in the repository: the
file is excluded from the deploy and must be edited on the node. Roles ride in
the token, and `manager` already does, so no new login is needed.

## Open

`POST /reset-password` still accepts a password typed by the operator, and no
protected principal is configured. Neither changed here.
