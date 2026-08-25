# Evaluation remediation and god-service decomposition — 2026-08-24

Source: `docs/evaluations/EVALUATION-2026-08-23-CLAUDE-FABLE-5.md` (evaluations
are local and gitignored; the tracked prompt is `EVALUATION-PROMPT.md`).

Deployed to all three servers on 2026-08-24, one at a time per the manual
policy in `config.json`.

## Security fixes

**Vault signature verification honored only RSA/PKCS#1 on the cached path.**
`KeyVault.VerifyAsync` dispatched on the version's own JWK when reading from
the database but hardcoded RSA with PKCS#1 padding when reading from the
snapshot cache — which is enabled by default. Every ES256 and PS256 signature
was therefore rejected as invalid in any deployment not using RS256. The
existing algorithm-agility tests could not catch it: their harness builds
`KeyVault` with no snapshot cache, so only the database path ran.

**Decrypt key lookup was not restricted by purpose.** A self-describing
ciphertext names its own key, and that name is attacker-influenced, so a
crafted `v1.oidc-signing:1.…` blob reached a signing key's wrapped private
material. Not exploitable (an unwrapped PKCS#8 key is not 32 bytes, so AES-GCM
rejected it) but the separation was conventional rather than enforced.

**Credential hints stored plaintext secret material.** `SecretHint` held the
last six characters of the client secret next to its PBKDF2 hash. It is now an
8-character fingerprint of the stored hash — derived from the hash rather than
the secret so the fast digest does not become a cheaper guessing oracle than
the slow hash beside it. Runbook `093` scrubs pre-existing rows; production had
none, because the additional-credentials feature was never used there.

**M2M refusals reported the wrong cause.** SCIM requires MFA by default, which
a client-credentials token can never satisfy — it authenticates an application,
so it carries no `amr`. Every 403 was audited as `scope_denied`, pointing
operators at the one thing that was not wrong. Denials now distinguish
`mfa_required_unsatisfiable_for_client_credentials` and log the appropriate
control (mTLS or `private_key_jwt` client authentication).

**Swagger published unconditionally, including production.** Both endpoints are
anonymous. Publication is now `Sufficit:Identity:Swagger:Enabled`; unset
publishes in Development only. This reverses a previously deliberate decision,
at the repository owner's direction, and the two architecture tests that pinned
the old intent were rewritten rather than deleted.

## Audit volume and cost

**SCIM read auditing moved off the request path.** Every SCIM `GET` persisted a
row and called `SaveChanges` before it could answer, so a polling client
amplified a read-only workload into sustained writes. Reads now queue through a
bounded channel drained by a background worker. Mutations deliberately keep
their in-transaction audit: committing the record atomically with the change it
describes is the whole point of auditing a privileged action.

**The audit table had no retention at all.** Append-only, written on every
privileged operation, and nothing ever removed a row. `ManagementAuditRetention`
`Worker` prunes past `Management.AuditRetentionDays` (default 15 — the trail
exists to detect wrong behavior, and an operator who has not noticed within a
fortnight will not notice in month eleven). Deletion is batched with a pause
between batches: one unbounded `DELETE` over months of history holds locks long
enough to stall live requests, and multimaster replication propagates that.

**Administrative surfaces were unthrottled.** The limiter covered `/connect/*`
and `/account/*` only. It now covers the management API and SCIM, with
whole-collection commands in a separate bucket — their cost profile is inverted
(one request, much server work), so a shared budget would produce 429s caused by
unrelated legitimate traffic in either direction. Repeated identical refusals
also collapse to one audit row per operator/capability/resource per window.

## Refusal auditing: a rule, not a sweep

Twelve services had hand-rolled the same authorize-and-audit pair, and the
copies had drifted: four audited refusals, six discarded them silently, one had
already invented a flag to choose. `ManagementOperationGuard` makes the choice
an explicit argument at the call site instead of a property of whichever copy a
service inherited — unifying it outright would have silently changed behavior in
either six services or four.

The rule applied: **record a refusal when success would have changed privilege
or exposed a secret.** It selects by capability, not by service, so refused
reads — the highest-volume, lowest-signal case — stay silent.

| Audited | Silent |
|---|---|
| `VaultSecretsResolve`, `VaultSecretsManage` | `VaultSecretsRead` |
| `ClaimsCreate/Update/Delete` | `ClaimsRead` |
| `ScopesCreate/Update/Delete` | `ScopesRead` |
| `ManagementTokensIssue/Revoke` | `ManagementTokensRead` |

This closed a real gap: a refused attempt to resolve a secret or to grant
oneself a claim previously left no trace, and those are the two clearest
privilege-probe signals on the surface.

What makes the rule safe is that `ManagementOverviewService` evaluates
capabilities as *discovery* — deciding which modules to render — through
`EvaluateAsync` rather than `DemandAsync`, so it never produces refusal rows. An
"audit all denials" sweep would have turned every page load by a limited
operator into writes.

## Decomposition

`ClientManagementService` was doing four jobs in one 3,230-line type. Five
policy types (`ClientJwksPolicy`, `ClientUriPolicy`, `ClientPermissionPolicy`,
`ClientTokenLifetimePolicy`, `ClientCredentialPolicy`) and
`ClientCredentialRegistry` now hold what it was carrying: **3,230 → 1,704
lines**. Every extracted policy is a pure function of its inputs, so each move
is compiler-verified; the registry became possible only once the shared guard
existed, which is what kept it from minting a thirteenth copy of the
authorize-and-audit pair.

`src/sts/ServiceCollectionExtensions.cs` had the same shape: **2,073 → 1,337**,
with certificate material and the OpenIddict server configuration extracted. The
latter needed care the management extractions did not — DI registration order is
load-bearing here and no test covers that ordering, so the safe move was the one
that changes no ordering at all: the `AddServer` lambda still runs at the same
point in the same sequence, and only its ~580 lines of text relocated. Its
closure captures became explicit parameters.

What remains in `AddSufficitIdentitySTS` is genuinely sequential composition,
where the ordering *is* the logic.

## Corrections to the evaluation

Three findings did not survive verification and are corrected in the document
rather than quietly dropped:

- the claimed `vault → management` layering inversion **does not exist** —
  `vault` references only `core` and `Application.Abstractions`, and both
  contracts are declared there. A namespace naming smell, not a cycle.
- **splitting the `DbContext` is withdrawn.** `OnModelCreating` is already 17
  cohesive methods, none over 137 lines, and the split's cost lands on
  hand-sequenced production SQL across a multimaster cluster.
- Swagger in production was a **deliberate, test-pinned decision**, not an
  oversight.

## Superseded by upstream

PR #36 (`identity.mcp` scope) landed while this work was in flight and solves
the same problem better: the scope name is consistent with
`identity.management`, and `McpScopeProvisioner` creates the scope and grants it
to trusted clients at startup, which removes the 403 window this branch's
version would have opened. This branch's `ManagementOptions.McpRequiredScope`,
its hardcoded registration and its two scope-gate tests were dropped in favour
of it.

## Verification

858 tests pass; the Release build is warning-clean. Each security fix ships with
a test that fails without it — the vault, MCP and SCIM-read defects all existed
*because* of missing coverage, so proving the new tests catch them mattered more
than adding them.

One defect only production could show: the retention worker's batched delete
used `Take(...).ExecuteDeleteAsync()`, which EF translates to
`DELETE ... WHERE id IN (SELECT ... LIMIT n)`. MariaDB rejects that shape
outright, so every sweep threw, was caught by the worker's own handler, logged a
warning and moved on — retention never removed a row. SQLite translates the same
LINQ differently and the suite passed. Found by checking the table after
deploying rather than trusting the deploy's success message; fixed by
materializing the batch ids first. Confirmed on production: 837 → 191 rows,
nothing older than the window.
