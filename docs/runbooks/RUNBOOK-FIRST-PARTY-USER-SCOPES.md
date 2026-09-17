# First-party user scopes: Genius and Fleet

A first-party application can reuse its user's Identity login for another Sufficit
resource. This does not require a personal API token. The resource server still
validates issuer, audience, scopes, subject and current user entitlements.

`Sufficit:Identity:FirstPartyUserScopes` is an explicit administrator-approved
mapping from client ID to additional user scopes, empty by default. Every mapped
scope must exist and the client must hold `scp:<scope>`. Missing registration or
permission never adds the scope. Scope resources determine token audiences.
The policy runs for authorization/device user grants and refresh; it is not applied
to client credentials or token exchange.

For the existing Genius client, preserve all existing permissions and add only
`scp:fleet.api`. Preserve the existing `fleet.api` scope resource `sufficit_fleet`.
Configure all Identity nodes:

```ini
[Service]
Environment="Sufficit__Identity__FirstPartyUserScopes__sufficit-ai-genius__0=fleet.api"
```

Deploy through the coordinated cluster procedure. Existing clients must omit the
optional `scope` field on refresh to receive the issuer's complete updated grant.
Sending the old scope explicitly requests a reduced response. This is not a
client-side request to broaden scopes: only the server's explicit mapping can add
them. The new Genius enrollment also requests fleet.api after the registration is
updated. Preserve refresh tokens, subject, session and existing audiences.

This configuration is an authorization decision for that first-party client.
Do not add unrelated clients or management scopes. Removing the mapping only stops
new implicit additions; revoke already issued grants when withdrawing access.
No default policy grants Fleet permissions to users or broadens tenant access.

Validation: FirstPartyUserScopeTests exercises registration/permission/configuration,
other clients, machine grants and an actual legacy-device refresh with introspection.
