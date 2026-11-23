# November operational review

Read-only production observations taken on 23 November 2026 around 15:52 UTC.

## Disabled client registrations

All ten registrations listed in the [October migration](202610271500-hyphenated-client-ids.md)
still have their disabled marker and a hyphenated successor. The retained token
table has zero rows issued to them since their disable timestamp on 27 October
at 19:56:23 UTC, and zero currently valid, unexpired or open-ended tokens.
Daily usage aggregates show zero events for them from 28 October to the check.
These queries describe retained evidence. Five registrations still have one
authorization each marked valid. Database foreign keys from authorizations
and tokens use RESTRICT. Permanent removal needs an explicit decision covering
the five authorizations and a supported deletion path. All ten registrations
remain disabled.

## Operator scope grants

The production configuration files on all three application nodes specify Observe.
The management audit spanned 22 October through 23 November and contained
159,465 rows. No reason code had the scope_grant_ prefix. Since 28 October
the client/scope capability search found two client-create events, one
successful and one denied. This sample offers limited evidence about the
impact of enforcement. A2.1 remains open.

## Token decryption

All three production configuration files still list the dedicated encryption
certificate followed by the two legacy decryption certificates. At the time
of this check there were zero retained valid, unexpired or open-ended tokens
with a missing creation date or one before 24 October UTC. That cutoff includes
the October rotation day. The query does not identify the encryption key used
for tokens issued later. Before removing the old entries, verify current issuance
against the dedicated key and prepare the configuration rollback. See the
[separation record](202610231600-encryption-certificate-separation.md).

## Plan reconciliation

The November 9 email-confirmation correction and the two confirmation deployments
have complete activity records. Their remaining evidence was merged into those
activities and their redundant plan files were retired. The production decisions
above are tracked in the existing authorization, keys and production plans.

## Authorized client retirement

On 23 November the operator authorized retirement of the ten
disabled registrations and their five remaining authorizations. The management
API returned 204 for each deletion. Its transaction deletes dependent tokens,
authorizations and credentials before deleting the application. Independent
database checks found zero remaining legacy registrations and all ten named
successors. The management audit recorded successful deletions for ten distinct
target client IDs between 15:57:20 and 15:57:25 UTC.

## Scope enforcement and decryption review at 16:00 UTC

All three application nodes configured Observe and 18 privileged scope entries
under Management/ClientScopeGrants. Each node listed the dedicated decryption
key first, followed by the two legacy certificates. The service environments
contained no scope-grant or encryption-path overrides.

The management audit contained zero rows matching either the scope grant reason
prefix or the observe authorization marker. Client/scope capability events
since 28 October included two successful client creates, two creates denied
for a missing general capability and the ten authorized retirements.
Those retirements do not exercise scope expansion. Switching to Enforce
would reject privileged scope additions by operators lacking the grant
capability. Existing privileged grants retained on a client edit have focused
regression coverage. Activation is an outstanding production decision.

For retained valid or inactive tokens with a future or open-ended expiry, the
database aggregated the public key identifier from five-part encrypted payload
headers. The snapshot contained 478 access tokens and one device code, all
with the same key identifier beginning 5B741AE3, matching the October dedicated
certificate record. No qualifying recorded token had an unknown creation time
or a creation date before 24 October. A separate snapshot counted 12,895 valid
refresh tokens with no stored payload, preventing direct verification of their
key identifiers. Signed-only tokens are outside the decryption-key count.

The Release run of ClientScopeGrantAuthorizationTests and CertificateRotationTests
passed all 17 tests. The review made no production configuration change.
For a subsequent certificate cutover, retain the files, back up the per-node
configuration, change only EncryptionPaths and verify a pre-cutover refresh
token from an operator-controlled test account before completing the rollout.
Restoring the previous list and restarting under the cluster procedure is the
configuration rollback. This review did not exercise that refresh flow.
