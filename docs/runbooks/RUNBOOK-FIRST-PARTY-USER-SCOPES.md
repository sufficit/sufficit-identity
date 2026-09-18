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

Add the following mapping to the existing `Sufficit.Identity` section in each
node's active `appsettings.Production.json`, preserving all other properties:

```json
{
  "Sufficit": {
    "Identity": {
      "FirstPartyUserScopes": {
        "sufficit-ai-genius": ["fleet.api"]
      }
    }
  }
}
```

Do not put that dictionary key in a systemd `Environment=` name: the hyphens
in `sufficit-ai-genius` make it an invalid environment variable name and systemd
ignores the assignment. Apply the JSON configuration as a separate audited
change under the deployment lease, retain a protected backup, then restart
through the coordinated cluster wrapper. Verify with a real legacy-client refresh
and resource request; a healthy process alone does not prove the mapping loaded.

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
