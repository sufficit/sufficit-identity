# PLAN — Token exchange, CIBA and dynamic registration

Status: B3.1 completed on 2026-11-06; remaining items queued.

[Index and delivery rules](PLAN-IDENTITY.md) · [Item-by-item reconciliation](../activities/202611061100-plan-reconciliation-split.md)

## Scope and order

B3 holder exchange is corrected; production inventory remains a rollout gate. CIBA expansion requires abuse/interoperability evidence. B9 remains explicitly deferred. DCR secret work depends on A2.

## Acceptance

Holder-bound exchange succeeds once and rejects foreign/replayed proofs; new lifecycle paths have authorization and negative tests; no compatibility removal without evidence.

Operational statuses describe evidence still required; historical records are not
a fresh production inventory. Source/tests present does not mean deployed.

## B3 — Token exchange provenance and delegation

B3.1 is closed in the [holder-bound exchange activity](../activities/202611061228-dpop-subject-token-exchange.md).
The original skipped regression now passes, together with wrong/missing ath,
foreign key, replay, fresh proof and nonce challenge/retry coverage.

- [ ] **B3 rollout · operational** — Refresh the production caller inventory before
  publishing this change. The old plan's absence of callers is historical only.
  This retains the original B3.1 rollout gate, not an unverified deployment claim.

## B5 — CIBA trust boundary completion

Initiator authentication, foreign clients, polling and one-winner consumption have tests; those do not establish external interoperability or approval-fatigue protection.

Evidence: [CibaTests.cs](../../src/tests/CibaTests.cs), [TwoReplicaSmokeTests.cs](../../src/tests/TwoReplicaSmokeTests.cs).

- [ ] **B5.1 · partial** — Run CIBA external interoperability/conformance and approval-fatigue abuse tests before additional clients. Reuse existing authentication, one-shot/concurrency and previous-release request tests.

## B9 — FAPI 2.0: how an expired `request_uri` is reported **(deferred by decision)**

Existing conformance documentation accepts the server error-page review path. Retain the owner-directed deferral; do not treat it as an urgent protocol failure.

Evidence: [README.md](../../conformance/README.md), [202611030100-conformance-healthcheck-dependabot-locks.md](../activities/202611030100-conformance-healthcheck-dependabot-locks.md).

- [ ] **B9.1 · deferred** — Resolve the client's registered redirect URI before the refusal, and only when the registration leaves no ambiguity — **revisit only if a client ever needs the machine-readable error.** No authorization is granted and the user is told either way.

## F10 — Dynamic client registration lifecycle

RegistrationController exposes POST creation, not the protected DCR lifecycle. Caller-supplied secrets remain an opt-in; a migration deadline/audited adapter is not provided by the default-off flag.

Evidence: [RegistrationController.cs](../../src/sts/Controllers/RegistrationController.cs), [McpOptions.cs](../../src/sts/Options/McpOptions.cs).

- [ ] **F10.1 · partial** — Add protected dynamic-registration read/update/delete and secret-rotation lifecycle with audit. Reuse the existing POST registration, canonical metadata validation and initial-access-token policy.
- [ ] **F10.2 · partial** — For opt-in caller-supplied DCR secrets, add an audited deprecated adapter with entropy floor and retirement deadline. Default AllowCallerSuppliedSecrets=false already exists and must stay secure by default.
- [ ] **F10.3 · dependency** — Align DCR credential lifecycle with E2 and A2 secret references instead of creating an independent credential mechanism.
- [ ] **F10.4 · decision** — Revalidate current anonymous-public DCR exposure against the documented owner choice. Either require initial access tokens through the rollout process or document accepted risk, owner and review/expiry date; do not silently disable an existing client journey.

## Validation required when executing

Run the tests cited in the evidence and targeted regressions for the remaining
behavior. Record exact commands, outcomes, release/commit and limitations.
For UI changes use the repository design/browser workflow; for production gates
attach dated redacted evidence and rollback. Do not close an item solely because
a related type, test name or historical deployment exists.
