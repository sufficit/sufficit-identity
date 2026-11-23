# Production OAuth manifest inventory and adoption

1. Completed. Inventory tracked manifests and reconcile declared clients with production registrations and management ownership.
2. Completed. Assess adoption candidates, unmanaged consumers and differences that need API preview or owner review.
3. Completed. Document and validate the read-only inventory and remaining adoption work on main.
4. Completed. Run audited inventory and preview for the Chrome Extension candidate.
5. Blocked. Resolve external scope references before applying adoption. Repeat inventory and preview and require exactly one client adoption.
6. Pending. Review broader client coverage and shared scope ownership before changing enforcement.

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
