# Production OAuth manifest inventory and adoption

1. Completed. Inventory tracked manifests and reconcile declared clients with production registrations and management ownership.
2. Completed. Assess adoption candidates, unmanaged consumers and differences that need API preview or owner review.
3. Completed. Document and validate the read-only inventory and remaining adoption work on main.
4. Pending operator access. Run audited inventory and preview. Reconcile the shared scope ownership, approve exact changes, apply the selected adoption and verify the resulting client.
5. Pending. Account for active clients outside the tracked manifests before deciding any wider enforcement scope.

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
