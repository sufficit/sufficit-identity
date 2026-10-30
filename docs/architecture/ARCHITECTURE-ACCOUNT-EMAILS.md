# Multiple email addresses per account

> **Status:** PROPOSED — tracked as **F15** in
> [`PLAN-IDENTITY.md`](../plans/PLAN-IDENTITY.md). Nothing here is built yet.

## Problem

An account has exactly one `Email` and one `UserName`
(`src/core/Entities/ApplicationUser.cs`). People don't: the same person often
holds a personal address and a work address, and signs in with whichever the
current device remembers. Today the only ways to express that are:

- **Linking several external logins** (`userlogins`) — works for sign-in, but
  the provider's address is never stored, so it can't be used for lookup,
  recovery, linking by address, or shown to the user.
- **An administrator rewriting `Email`/`UserName`** — loses the old address
  completely, and in practice has been done straight in the database because
  the admin flow requires an MFA admin session
  ([`202610301530`](../activities/202610301530-nilza-username-empresarial.md)).
- **Two accounts** — splits entitlements, history and authorizations, which is
  what the user wanted to avoid in the first place.

## Decision

An account owns a **set of email addresses**. Exactly one of them is
**primary**; the rest are **secondary**. `users.Email` stays as the projection
of the primary address, so ASP.NET Core Identity, token issuance and every
legacy reader of the `users` table keep working unchanged.

| Concept | Rule |
|---|---|
| Ownership | A normalized address belongs to at most one account, primary or secondary, across the whole store. |
| Proof | A secondary address is usable for anything only after it is confirmed. An unconfirmed secondary resolves to nothing. |
| Primary | Must be confirmed (except the legacy primary carried over by backfill, which keeps its current `EmailConfirmed`). |
| Username | Independent of the address set. Changing the primary never renames the account implicitly. |
| Token claims | `email` / `email_verified` keep meaning the primary. Secondaries are not released in tokens. |
| Limit | Configurable cap per account (default 5) so the set can't become an address-harvesting store. |

`sub` is the identity. Addresses are ways to reach and find the account,
never its key.

## Data model

New table, additive migration `110-add-user-emails.sql`:

```
useremails
  id                  varchar(36)  PK
  userid              varchar(255) FK users(id) ON DELETE CASCADE
  email               varchar(256) NOT NULL
  normalizedemail     varchar(256) NOT NULL  UNIQUE
  isprimary           tinyint(1)   NOT NULL
  confirmedatutc      datetime(6)  NULL
  source              varchar(32)  NOT NULL  -- self | management | scim | backfill
  createdatutc        datetime(6)  NOT NULL DEFAULT utc_timestamp(6)
  INDEX (userid)
```

The primary address is **also** a row (`isprimary = 1`). That way a single
unique index on `normalizedemail` enforces the cross-account invariant; no
cross-table check, no race between `users.normalizedemail` and the new table.
A partial "one primary per user" rule is enforced by the write service inside
the same transaction (MariaDB has no partial unique index).

Backfill copies every `users.Email` that is not null as the primary row,
`source = backfill`, `confirmedatutc` = migration time when `EmailConfirmed = 1`.
The unique index from `108-unique-normalized-email.sql` guarantees the backfill
can't collide.

## Write paths

All mutations go through one service (`IAccountEmailService`), which holds the
transaction, keeps `users.Email`/`NormalizedEmail`/`EmailConfirmed` equal to
the primary row, writes `managementauditevents` and publishes the security
event. Nothing else writes `useremails` or `users.Email`.

| Operation | Self-service (`/manage/emails`) | Management API | SCIM |
|---|---|---|---|
| Add secondary | Recent authentication; confirmation link sent to the new address; row exists unconfirmed until the link is used | Same, or `confirmed: true` with mandatory `reason` (audited) | `emails[]` non-primary entries; confirmed according to the SCIM client's trust setting |
| Confirm | Link from the confirmation mail (single use, short-lived, bound to the row id) | — | — |
| Remove secondary | Recent authentication | Allowed | Removing it from `emails[]` |
| Make primary | Recent authentication + MFA when enrolled; target must be confirmed | Allowed; target must be confirmed unless `reason` | `primary: true` entry |
| Remove primary | Never — make another one primary first | Never | 400 |

Management routes, under the existing `api/users`:

```
GET    api/users/{id}/emails
POST   api/users/{id}/emails                    { email, confirmed?, reason? }
POST   api/users/{id}/emails/{emailId}/primary  { reason? }
DELETE api/users/{id}/emails/{emailId}
```

Capability: the existing `identity.users.update`; no new permission name.

`UserManagementService.UpdateProfile` stops writing `Email` directly: an email
change there becomes "add confirmed address + make primary" through the same
service, so the profile form and the new routes can't diverge.

Side effects:

- **Make primary** updates the security stamp (the `email` claim changes) but
  does **not** revoke tokens or authorizations — the account, its sign-in
  methods and its grants are the same. It notifies the **previous** primary
  address ("your sign-in email was changed") so a takeover is visible to the
  real owner.
- **Add/remove secondary** notifies the primary address. No stamp change.
- Every operation emits an SSF/CAEP-style account event through the existing
  publisher, so relying parties that cache the email can refresh.

## Read paths

`IAccountLookupPolicy.FindUniqueByEmailAsync` (`src/sts/AccountLookupPolicy.cs`)
is already the single choke point for address lookups (interactive login with
`UseEmail`, passkey, CIBA `login_hint`, onboarding, recovery, external
linking). It changes from `users.NormalizedEmail` to `useremails.normalizedemail`
with `confirmedatutc IS NOT NULL`, still rejecting ambiguity. Every caller gets
secondary-address support without being edited, and none of them can resolve
an unconfirmed secondary.

Consequences per flow:

- **External identity linking** — a provider address equal to a confirmed
  secondary links to that account under the existing
  `IExternalIdentityLinkingPolicy`; the pre-hijack protection in
  [`ARCHITECTURE-EXTERNAL-IDENTITY-LINKING.md`](ARCHITECTURE-EXTERNAL-IDENTITY-LINKING.md)
  is unchanged because unconfirmed rows never match.
- **Unconfirmed-account claim** (`ClaimUnconfirmedAccountAsync`) only considers
  the primary; a secondary can't be used to wipe an account's credentials.
- **Password recovery** — the mail goes to the address that was typed, if it is
  a confirmed address of the account. The response stays identical whether or
  not anything matched, and the other addresses are never revealed.
- **Registration** — an address that is a confirmed secondary of another account
  is "already in use", same as a primary today. An *unconfirmed* secondary
  doesn't block registration; the pending row is dropped when the new account
  confirms that address (whoever proves it first owns it).
- **Password form** — still username-only
  (`PasswordLoginController`); allowing "username or any confirmed address" is
  a separate decision, listed under open questions.
- **Tokens and userinfo** — unchanged: `email` = primary.

## Rollout

Additive, under `Sufficit:Identity:Accounts:SecondaryEmails`:

1. Migration 110 + backfill; service dual-writes (`users.Email` and the
   primary row) on every existing email write path. Flag off: lookups still
   read `users`.
2. Parity check job: every `users.Email` has exactly one matching primary row;
   report drift as a posture finding.
3. Switch `AccountLookupPolicy` to the new table (flag `Lookup=true`), observe.
4. Enable the management routes and console page, then the self-service page.
5. SCIM full `emails[]` mapping last, per client.

Rollback at any phase = flag off; `users.Email` stays authoritative for every
reader that predates this design.

## Tests

- Uniqueness races: two accounts adding the same address; add vs. registration;
  SCIM vs. self-service (extends F9).
- Unconfirmed secondary never resolves in login, passkey, CIBA, recovery or
  external linking.
- Make-primary keeps `users.Email`, `NormalizedEmail` and `EmailConfirmed` in
  step with the row, updates the stamp, keeps tokens, notifies the old address.
- Removing the primary or the last confirmed address is refused.
- Recovery response is indistinguishable for matched/unmatched/secondary.
- Cap per account enforced on every path.
- Fresh-install schema equals upgraded schema at HEAD.

## Open questions

- Should the password form accept any confirmed address in addition to the
  username?
- Should a relying party be able to request secondaries through an allow-listed
  claim (e.g. `emails`), or never?
- Per-domain rules: may an administrator force the primary to be an address in
  a given domain for members of an organization?
- Should external logins remember the provider address (display only) so the
  user can see which account each link is?
