# Production OAuth manifest inventory and adoption

1. Completed. Inventory tracked manifests and reconcile declared clients with production registrations and management ownership.
2. Completed. Assess adoption candidates, unmanaged consumers and differences that need API preview or owner review.
3. Completed. Document and validate the read-only inventory and remaining adoption work on main.
4. Completed. Run audited inventory and preview for the Chrome Extension candidate.
5. Completed. Verify current OAuth consumers and design explicit external scope references with pre-write validation.
6. Completed. Implement and test the provisioner support and update the Chrome Extension manifest and OAuth request to entitlements.
7. Completed. Commit and push verified source. Record release sequencing and any production verification still required.
8. Completed. Publish the provisioner on all three nodes and verify production health.
9. Completed. Obtain audited preview of the transitional Chrome manifest.
10. Completed. Apply the reviewed transition and verify scope owners, permission grants and auditing.
11. In progress. Chrome Web Store 2.23.0 is published and the distributed package requests `entitlements`. The maintainer confirmed a successful interactive login. Verify migration of installed versions before retiring the `directives` client permission.
12. Pending. Review broader client coverage and shared scope ownership before changing enforcement.

## Production snapshot, 23 November 2026

The read-only reconciliation checked 107 local repository copies using their
available origin/main references, with HEAD as a fallback. It found nine unique
tracked provisioning manifests after deduplicating working copies, seven distinct
clients and ten distinct scopes. This is an inventory of the repositories present
in the workspace. The live database contained 60 registration rows, one marked
disabled. Of the 53 registrations outside these manifests, 26 had a recorded
token issuance in the daily aggregate between 25 August and 23 November. Thirteen
outside registrations use the dynamic-registration ID format. These groups
overlap. All six registrations carrying the provisioning ownership marker matched
an inventoried client.

| Repository manifest | Production client ownership |
| --- | --- |
| Background, Cloud Mobile, Landing Pages and Network Control | Four existing clients managed by the expected manifests |
| Phone Desktop and Telephony Panel | Two existing clients managed by the expected manifests |
| Chrome Extension Phone | Existing public client with no provisioning owner marker |
| AI and Endpoints | Scope-only manifests |

The seven clients matched the compared registration fields including types,
permissions, redirect and logout URI sets, PKCE and managed logout settings.
The Chrome Extension manifest explicitly requests adoption and declares no
scopes of its own. Start with an audited inventory and preview of that
single-client manifest. Require the preview to report exactly one adoption.
Review the behavior diff before applying.

The ten scope resource sets and entitlement claim sets matched the declared
values. Background and Network Control declare existing scopes without an owner
marker, and their descriptions differ. Cloud Mobile and Telephony Panel both
declare the entitlements scope. Production records Telephony Panel as owner and
matches its description. The AI legacy bridge scope also has a description
difference. Resolve ownership and text differences before any broader apply.
The scope provisioner can update a scope owned by a different manifest.

The live inventory endpoint returned HTTP 401 without operator credentials.
Audited inventory and preview require `identity.provisioning.preview`.
This snapshot used read-only database queries and did not exercise the API
preview or confirm full descriptor equality. No application or scope was changed.

## Audited Chrome Extension preview, 23 November 2026

The inventory endpoint rejected the versioned manifest from commit
`83620f9b59e13466e6e1e55082888b3fd91e1061` with HTTP 400. Its client asks
for chrome.phone, endpoints.phone and directives. The validator requires
custom scopes to be declared in the same manifest. Production attributes
the first two scopes to the Endpoints manifest and the third to Cloud Mobile.

A diagnostic request included the current resource sets, descriptions and
entitlement claims of all three scopes. Inventory returned HTTP 200 and
DeclaredUnmanaged for SufficitChromeExtension. Preview returned HTTP 200
with one Adopted client and three Update scope operations. The provisioner
stamps the submitting manifest as owner on those scope updates. The diagnostic
request is unsuitable for apply.

The management audit contains a successful inventory and preview, and the
production registration still has no provisioning owner. Adoption is blocked
on a provisioner change that can validate referenced existing scopes without
rewriting them. A future acceptance check must require exactly one Adopted
client, zero scope operations, and a read-back of the original scope owners.

## External scope references and Chrome migration

`referencedScopes` is optional in manifest version 1. It names custom scopes
that must exist in the target Identity database. Inventory, preview and apply
validate their existence, and apply checks them before any manifest writes.
A scope name can appear in one of `scopes` or `referencedScopes`. Existing
scope-grant authorization still applies to the client’s requested permissions.
References produce no scope operations, so the owning manifest and attributes
are preserved.

Chrome Extension commit `64e05f3` uses `entitlements` for new sign-ins.
Its manifest references chrome.phone, endpoints.phone and entitlements. The API
audience still comes from chrome.phone. Production inspection found that the
current client permits directives and lacks entitlements. Fifteen enabled
registrations still permit directives across Identity. This change is scoped
to the extension’s migration.

Release order:

1. Publish the Identity provisioner and obtain a fresh audited inventory and
   preview. Use a transitional copy of the versioned Chrome manifest that also
   references directives and retains that client permission during the store
   rollout. Require exactly one client adoption and zero mutations to scopes.
2. Confirm the grant diff and apply with an authorized operator. Verify client
   ownership, preserved scope owners, and both login paths.
3. Publish the Chrome Extension through its own store workflow. Retire the old
   client permission after confirming the supported installed versions can sign
   in using entitlements. The tracked Chrome manifest records that final state.

Validation included 45 focused tests and 2,182 tests in the local Identity
solution excluding the separate browser suite. The Release build passed
with warnings treated as errors. Chrome passed lint, package build, 81 Node
tests, 224 .NET tests and the browser suite. One Node test was skipped.

The isolated Identity package `20261123-3798a917` passed the release helper
checks. It contains revision `3798a9176366dad079c25cb757bad1b98ffd2002`
and SUI revision `1d09b4a62a0694a6094a42bcdf78cc508c61a5f4`. Archive
SHA-256 is `ff54c802cf6ac07cc8ed160ec400ad07a27c4209693e6eae98f4d34457155b48`.
Production was healthy and uniform on 48becb9c when checked. The source diff
contains no schema migrations. The production rollout is recorded below.

## Provisioner rollout, 23 November 2026

The maintainer authorized the production rollout. GitHub CI, CodeQL and package
publication succeeded for revision 3798a917 before activation. Staging validated
the archive and inherited four local configuration files on each node. The
cluster lease serialized activation across Eveo, Apoint and Castrum. Direct
health probes briefly returned HTTP 502 during restarts. Each node recovered
before activation advanced and the previous release was retained for rollback.

All three nodes report revision 3798a917 and passed liveness and readiness.
Certificate and JWKS hashes match the baseline. Public health, readiness,
discovery and login returned HTTP 200. The preview API returned HTTP 401
without a current operator credential.

The Chrome client still permits directives and lacks entitlements. Endpoints
owns chrome.phone and endpoints.phone, Telephony Panel owns entitlements,
and Cloud Mobile owns directives. The transitional preview input is the
manifest at 64e05f3 with directives appended once to referencedScopes and
to the client's scope list. It contains zero managed scope definitions.
Encoding the JSON as sorted keys, compact separators and UTF-8 produces SHA-256
`981d8054f95b17b0b17dd7924cfdf389bcf2b31812c234c2d302c6bea2e4af49`.
The authorized scope of this rollout was the provisioner publication.
The Chrome adoption and permission change await audited preview.

## Transitional adoption preview

Production inventory and preview returned HTTP 200 for the pinned transitional
manifest. Inventory reported DeclaredUnmanaged for SufficitChromeExtension.
Preview returned exactly one change, Adopted for the Chrome client. It returned
zero scope operations. This proposal adds the entitlements grant and lets
installed versions continue using directives during the store transition.
Inventory correlation ID was `0HNQ9KDQ9PLC4:00000001`. The client still has
its original registration and scope grants. Applying the proposal requires
an authorized operator with `identity.provisioning.apply`.

## Transitional adoption applied

The approved request with the recorded SHA-256 returned HTTP 200 and one
Adopted operation for SufficitChromeExtension. Production read-back verified
the new manifest owner and all 14 expected permissions, including entitlements
and directives. It also verified the registered public type, explicit consent,
three callbacks, PKCE and logout settings against the manifest. The initial
raw JSON fingerprint comparison did not match. The semantic checks above
verified the OAuth fields independently.

The response had zero scope operations, and subsequent queries showed the
same four owners for chrome.phone, endpoints.phone, entitlements and directives.
The audit recorded both provisioning_client_adopted and provisioning_manifest_applied
at 21:09:20 UTC. Two authorization requests without a session using PKCE
returned HTTP 302 and the expected login_required error at the registered
callback, one for each scope. This confirms both requests pass initial
validation. The interactive login result is recorded below.

## Chrome Web Store rollout

On 24 November 2026, the Chrome Web Store API reported `PUBLISHED` for
version `2.23.0` with 100% distribution. The CRX3 downloaded from Google's
update service contained `manifest.json` version `2.23.0` and requested
`openid profile email offline_access chrome.phone entitlements` in `js/oauth.js`.
The package confirms the scope migration shipped with extension commit `8c01354`,
which includes the OAuth change from `64e05f3`.

The maintainer confirmed a successful interactive login in the extension with
their own account after the rollout. This validates the tested installation.
The store percentage describes availability of the new release. The installed
version distribution remains unverified. The extension's version diagnostics can
be disabled and cover only clients that report events, so missing diagnostics
cannot establish that older installations have migrated. Keep the transitional
`directives` grant until legacy client usage has been assessed.
