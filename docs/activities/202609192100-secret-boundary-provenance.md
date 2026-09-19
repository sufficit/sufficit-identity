# Proving a secret came from the right place

Plan: `PLAN-IDENTITY.md` section C1, delivered and removed from it.

`EnsureNoPlaintextSecrets` already refuses startup when any of seventeen mapped
keys carries a value in configuration, and it runs unconditionally rather than
behind a migration flag — stronger than the plan item assumed. What did not
exist was any way to answer three adjacent questions.

## Where did each secret actually come from?

Nothing recorded it. After the override layer is appended, every value looks
the same to every consumer, so "production can prove its configuration-time
credentials came from the approved boundary" was not answerable.

`AddSufficitSecretOverrides` now returns a `SecretResolutionReport`: for each
mapped secret, its logical name, its configuration key, and one of
`SecretStore`, `Configuration` or `Absent`. The determination is cheap and
honest — build the configuration as it stands *before* appending the override
layer, and whatever answers there did not come through the store.

`SecretResolution` deliberately has no value field. The question is answerable
without reading the secret, so the type is built such that it cannot
accidentally be logged with one; a test asserts that neither the stale
configuration value nor the store's value appears in the report's `ToString`.

`SecretBoundaryPostureContributor` reports the fallbacks as an advisory during
the migration and as **blocking** once a deployment sets
`Sufficit:Vault:SecretMigrationComplete=true`. That is the whole point of
declaring it: before, a fallback is the state being migrated out of; after, the
next one is a regression that refuses startup.

## What about the secrets nobody mapped?

The gate knows seventeen keys. A resource secret, an API key added for one
integration, a second connection string — none of those are in the table, so
they sit in an appsettings file with nothing watching. This repository has had
exactly that: a `ResourceSecret` committed in two sibling repositories.

`FindUnmappedSecretLikeKeys` walks the configuration and reports keys that look
like credentials by naming convention and are not already mapped. Returns keys
only; the caller reports names, never values.

Convention matching is imprecise on purpose — a deployment reviewing a false
positive costs a minute, a missed credential costs more — but imprecise is not
the same as noisy, and the first version was noisy. Run against this
repository's own `appsettings.json.template` it produced **nine** findings, all
false:

- `LegacyGrants:Password` and `Mcp:Dcr:RequireInitialAccessToken` are
  **booleans**. A switch named after a secret is still a switch, and the ROPC
  one would have fired on every deployment.
- `_SigningPassword`, `_EncryptionPassword`, `_Password`,
  `_InitialAccessToken`, `_CertificatePassword` are this repository's
  **commented twins** — the convention of documenting a real key by placing an
  underscore-prefixed sibling beside it, holding guidance rather than a value.

So the matcher now skips underscore-prefixed leaves, anything that parses as a
boolean or a number, and `Require`/`Use`/`Is`/`Allow`-style prefixes, on top of
the existing `Name`/`Path`/`Lifetime` suffix exclusions. Against the template,
`deploy/local/appsettings.json` and `appsettings.Development.json` it now
reports nothing, and a test pins that: a scanner that fires on the shipped
configuration is one operators learn to skim.

It gained one rule in the other direction. A connection string carries its
credential *inside the value*, so the key name proves nothing —
`ConnectionStrings:Reporting` looks innocent and may still hold
`Password=...`. Any value containing `password=` or `pwd=` is reported
regardless of what the key is called.

## Is the file holding them readable by everyone?

A file permission is the last boundary around a value that made it into a file
anyway, and `deploy/local/appsettings.json` has already been mistaken for
production configuration once (evaluation 2026-08-15, H-1, where it was read as
evidence that ROPC was enabled in production — it was not).

The contributor walks the `FileConfigurationProvider`s actually loaded, checks
`UnixFileMode.OtherRead` on each physical file, and reports path and mode. The
contents are never read.

## Verification

1,448 tests pass, Release warning-clean. Twelve new tests; blinding the
provenance and the scanner makes four of them fail, which was checked rather
than assumed.

One registration defect found by the suite rather than by reasoning:
`TryAddEnumerable` with a factory lambda throws at container build —
"implementation type cannot be `IProductionPostureContributor` because it is
indistinguishable from other services registered for it" — and took out sixty
tests at once. `TryAddEnumerable` needs a concrete implementation type to
deduplicate against, so the report is registered as its own singleton with an
empty default and the contributor takes it as an ordinary dependency.
