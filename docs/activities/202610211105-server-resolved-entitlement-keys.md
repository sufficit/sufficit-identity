# Server-resolved entitlement keys enabled in production

Requested by the operator on 2026-10-21 (customer access to a consumer panel). Configuration only;
no code change and no new release.

- Nodes: app-node-1, app-node-2, app-node-3 (release `ff8c411`), one at a time.
- Change in `/opt/sufficit-identity/appsettings.Production.json` on each node:
  `Sufficit:Identity:ClaimScopeMap:ServerResolvedEntitlementKeys = ["orders.panel", "orders.monitor"]`.
  Nothing else in the file changed.
- Effect: these entitlement values are no longer released in access/identity tokens and are
  returned only by `GET /connect/userinfo?entitlements=current` under
  `authorization.grants`. Before this, the list was empty: the resource server received
  `grants: []` and the values leaked into tokens.
- Backups: `/var/backups/sufficit-identity/appsettings.Production.json.before-server-resolved-20261021T1105{10,22,34}`
  (app-node-3, app-node-2, app-node-1), root 0600.
- Verification: `/.well-known/openid-configuration` returned 200 through the local socket after each
  restart (4–8 s) and on the public URL; no warnings in the journal. `deploy.py` (R018) carries the
  live `appsettings*` into new releases, so the setting persists across deploys.
- Rollback: restore the backup on each node and restart `sufficit-identity`, one node at a time.
