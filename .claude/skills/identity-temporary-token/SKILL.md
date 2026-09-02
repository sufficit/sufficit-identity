---
name: identity-temporary-token
description: Request a short-lived, scoped management token for Sufficit Identity by handing the user a pre-filled confirmation link. Use whenever you need to change something in Identity — create or update an OAuth client, grant a scope, read or edit users, claims, sessions, authorizations, branding, vault secrets — instead of touching the database, editing seed code, or asking for a long-lived credential. Triggers: "create a client", "grant a scope", "add a redirect_uri", "look at that user's claims", "revoke a session", "I need access to Identity".
---

# Temporary management token for Sufficit Identity

You do not get standing access to Identity, and you should not want it. When a
task needs a change there, you build a link that describes exactly the access
you need, the user opens it and confirms, and you receive a bearer token that
expires on its own.

The point is that the human sees the request before it exists. A link that asks
for `identity.clients.update` is reviewable in a way that "give me the admin
password" is not.

## The flow

1. **Decide the minimum capabilities** the task actually needs.
2. **Build the link** (below) and give it to the user, saying plainly what you
   are going to change and why.
3. **The user opens it**, sees the purpose, the lifetime and the exact
   capability list already filled in, and confirms.
4. **The user pastes the token back to you.**
5. **You call the API** with it, do the change, and report what you did.
6. **You stop using it.** It expires by itself; do not write it to a file, a
   commit, a log, or a memory.

## Building the link

Base: `https://identity.sufficit.com.br/management/tokens`

| Parameter | Meaning | Rules |
| --- | --- | --- |
| `action` | Always `issue` — opens the issuance form directly | required for a one-click flow |
| `purpose` | Short human sentence shown to the user | ≤ 120 characters |
| `lifetimeSeconds` | How long the token lives | ≥ 60, ≤ the environment maximum; default 900 (15 min) |
| `capability` | One capability. **Repeat the parameter**, one per capability | must exist in the catalogue below |

`capabilities=a,b,c` (comma-separated, single parameter) is also accepted when
reading the URL, but prefer the repeated `capability` form — that is what the
page itself produces, and it survives values that contain commas.

Example — adding a redirect URI to an existing client:

```
https://identity.sufficit.com.br/management/tokens
  ?action=issue
  &purpose=Add%20the%20loopback%20redirect%20to%20sufficit-phone-desktop
  &lifetimeSeconds=900
  &capability=identity.clients.read
  &capability=identity.clients.update
```

Write it on one line when you send it. Percent-encode `purpose`.

## Using the token

```
Authorization: Bearer <token>
```

against `https://identity.sufficit.com.br/api/...`. The surfaces:

`clients` · `client-drafts` · `users` · `service-accounts` · `claims` ·
`scopes` · `sessions` · `authorizations` · `audit` · `branding` · `metrics` ·
`overview` · `mcp` · `integrations/oauth` · `database/connections` ·
`provisioning/manifest` · `provisioning/token` · `vault/secrets` ·
`vault/users` · `vault/personal/secrets` · `account/personal` ·
`account/tokens` · `operator-tokens`

Note the path: the **UI** lives under `/management/`, the **API** does not.
`/management/api/...` returns 404 — confirm with `/api/overview`, which answers
401 when unauthenticated.

`api/operator-tokens` is what the confirmation page itself calls. Do not try to
mint a token by calling it directly: it needs a token you do not have yet, and
going around the page removes the human review that is the entire point.

## Capabilities

Ask for the narrow one. **There is no catch-all capability**: the list below is
the whole vocabulary, so a task that needs three things names three things.

Do not put `identity.management` in `capability=`. Despite the name it is not a
capability — it is an OAuth scope and the break-glass claim value, and the
issuance page will refuse it.

| Area | Capabilities |
| --- | --- |
| Clients | `identity.clients.read` `.create` `.update` `.delete` |
| Users | `identity.users.read` `.create` `.update` `.delete` `.disable` `.reset` |
| Claims | `identity.claims.read` `.create` `.update` `.delete` |
| Scopes | `identity.scopes.read` `.create` `.update` `.delete` |
| Sessions | `identity.sessions.read` `identity.sessions.revoke` |
| Authorizations | `identity.authorizations.read` `identity.authorizations.revoke` |
| Audit / metrics | `identity.audit.read` `identity.metrics.read` `identity.metrics.manage` |
| Branding | `identity.branding.read` `identity.branding.manage` |
| Vault | `identity.vault.secrets.read` `.resolve` `.manage` |
| Provisioning | `identity.provisioning.preview` `identity.provisioning.apply` |
| Database | `identity.database.read` |
| Tokens | `identity.management.tokens.read` `identity.management.tokens.issue` `identity.management.tokens.revoke` |

The user must themselves hold `identity.management.tokens.issue` to use the
page. If they cannot issue, that is an access problem for them to resolve — not
something to route around.

## Rules

- **Never** propose editing the Identity database directly, changing seed code,
  or reusing a credential you found in a config file to make a change that this
  flow covers. The whole reason this exists is that those paths leave no record
  and no expiry.
- **Ask for read capabilities separately** when you only need to look. A read
  link is much easier for a user to approve quickly, and most investigation
  needs nothing more.
- **One token per task.** Do not keep one around for "the next thing" — build a
  new link, which is cheap and re-states the intent.
- **If the token expires mid-task**, say so and send a new link. Do not
  improvise another route to the same change.
- **Report what you changed**, including anything you touched beyond the
  literal request, so the user can audit against the purpose they approved.

## When this is not the right tool

- Reading public protocol metadata (`/.well-known/openid-configuration`,
  `jwks_uri`) — no token needed.
- Anything a machine account already holds a `client_credentials` grant for;
  use that instead of asking a human to click.
- Changes to application code or configuration in this repository — those are
  ordinary edits and a pull request, not an Identity permission.
