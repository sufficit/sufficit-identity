# First-party user scopes

A first-party application can reuse its user's Identity login for another
resource server of the same deployment. This does not require a personal API
token. The resource server still validates issuer, audience, scopes, subject and
current user entitlements.

`Sufficit:Identity:FirstPartyUserScopes` is an explicit administrator-approved
mapping from client ID to additional user scopes, empty by default. Every mapped
scope must exist and the client must hold `scp:<scope>`. Missing registration or
permission never adds the scope. Scope resources determine token audiences.
The policy runs for authorization/device user grants and refresh; it is not applied
to client credentials or token exchange.

Example: client `example-app` should call the resource server behind scope
`orders.api` (resource `orders-api`). Preserve the client's existing permissions
and add only `scp:orders.api`; keep the scope's resource as registered.

Add the mapping to the `Sufficit.Identity` section of each node's active
`appsettings.Production.json`, preserving all other properties:

```json
{
  "Sufficit": {
    "Identity": {
      "FirstPartyUserScopes": {
        "example-app": ["orders.api"]
      }
    }
  }
}
```

Do not put that dictionary key in a systemd `Environment=` name: hyphens in a
client ID make it an invalid environment variable name and systemd ignores the
assignment. Apply the JSON configuration as a separate audited change under the
deployment lease, retain a protected backup, then restart through the
coordinated cluster wrapper. Verify with a real refresh and resource request; a
healthy process alone does not prove the mapping loaded.

Existing clients must omit the optional `scope` field on refresh to receive the
issuer's complete updated grant. Sending the old scope explicitly requests a
reduced response. This is not a client-side request to broaden scopes: only the
server's explicit mapping can add them. Preserve refresh tokens, subject,
session and existing audiences.

This configuration is an authorization decision for that first-party client.
Do not add unrelated clients or management scopes. Removing the mapping only stops
new implicit additions; revoke already issued grants when withdrawing access.
No default policy grants resource permissions to users or broadens tenant access.
