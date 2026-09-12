# External identity linking

## Problem

An external provider asserts an email address. Asserting is not proving.
Several widely used providers never issue `email_verified`, and one that does
may be asserting something it never checked.

If an unproven assertion is enough to **create the local account and link**
the external identity, there is an early-hijack attack:

1. The attacker registers the victim's address with a provider that doesn't
   verify addresses and signs in to Identity.
2. The local account is born, `EmailConfirmed=false`, with the attacker's
   login linked to it. The attacker can't sign in yet, because the sign-in
   policy requires a confirmed email.
3. The victim tries to register and gets a generic error; tries to recover
   the password and nothing happens, because the account isn't confirmed.
4. The victim uses "resend confirmation," confirms the address — and the
   attacker's link survives the confirmation. From then on, the attacker
   signs in through the external provider, with a full session.

The step that breaks everything is step 2: **the link precedes the proof**.

## Decision

Nothing is persisted until control of the address has been established.

The decision of "has it been established?" is an explicit boundary,
`IExternalIdentityLinkingPolicy`
(`src/application/Sufficit.Identity.Application.Abstractions/Accounts/ExternalIdentityLinking.cs`),
with three answers:

| Decision | Meaning |
|---|---|
| `Immediate` | Control established; creates and links in the same request. |
| `RequiresEmailVerification` | Not established; nothing is persisted and a proof message is sent. |
| `Denied` | The provider may authenticate existing links, but may never create an account. |

The policy is a boundary, not an embedded condition, because the answer is a
deployment decision, not a protocol fact. A deployment whose only provider is
an in-house corporate IdP can trust its addresses; one that federates
consumer providers cannot. The same binary serves both without either editing
an `if`.

## Default implementation

`ConfigurableExternalIdentityLinkingPolicy` (`src/sts/ExternalIdentityLinkingPolicy.cs`)
evaluates, in this order: deny-list, the `RequireVerifiedEmail` key, the
provider's assertion, allow-list of trusted providers.

**No provider is named in code.** Which schemes exist, and which of them the
deployment trusts, is configuration
(`Sufficit:Identity:ExternalIdentities`, see `src/sts/Options/ExternalIdentityOptions.cs`).

## Flow with proof

```
provider callback
  └─ policy: RequiresEmailVerification
       ├─ PendingExternalIdentityStore.CreateAsync  → single-use ticket
       ├─ ExternalIdentityVerificationMessenger     → message to the address
       └─ response: EmailVerificationRequired  (no row written)

GET /account/externallink/confirm?ticket=…
  └─ IExternalSignInService.CompletePendingLinkAsync
       ├─ redeems the ticket (consumes before use)
       ├─ refuses if the address was already claimed in the meantime
       └─ creates the account ALREADY confirmed + links + signs in
```

Redeeming the ticket **is** the proof: it was only delivered to the address in
dispute, so whoever presents it controls the mailbox. That's why the account
is born confirmed — requiring a second confirmation would prove the same
address twice.

### Ticket properties

| Property | How |
|---|---|
| Single use | Removed before being used (`RedeemAsync`), so a replay finds nothing |
| Credential size | 256 bits from `RandomNumberGenerator` |
| Not readable in the database | The stored key is the SHA-256 of the ticket |
| Short window | `VerificationLifetimeMinutes`, default 30, capped at 5..1440 |
| Shared across replicas | Lives in `IProtocolStateStore` (`protocolstateentries` table), not in a cookie |

It carries no return URL. The proof is redeemed from the mailbox, commonly in
another browser, where the original authorization request no longer exists —
and a redirect destination that survives a message is one more thing to
validate.

## Legacy data

The current flow never links before proof, but accounts created under the
previous behavior still carry the link. `ConfirmEmailAsync`
(`src/sts/AspNetCoreIdentityAccountOnboardingService.cs`) removes external
logins from an account that was unconfirmed at the moment its legitimate
owner proves the address.

This is conditioned on `SignIn:RequireConfirmedEmail`. Only under that policy
is it **impossible** for a legitimate link to exist on an unconfirmed account:
linking a provider requires an authenticated session, and authenticating
requires a confirmed address. Without the policy, a user may legitimately
sign in without confirming and link a provider — and purging it would destroy
their work.

## Posture check

`StsProductionPostureContributor` reports two findings:

| Finding | When |
|---|---|
| `external-identity-unverified-email` | `RequireVerifiedEmail=false` |
| `external-identity-trusted-providers` | There are providers on the allow-list, listed in the text |

The second one is not an error: it's an auditable reminder that someone
decided to trust those providers.

## Tests

`src/tests/ExternalIdentityLinkingTests.cs` — policy decisions, single use of
the ticket, wiring in the composed host (the real server's default requires
proof), and both sides of the legacy purge: an unproven account loses its
links, an already-proven account keeps them.

The purge test was verified by mutation: with the purge turned off, it fails.
