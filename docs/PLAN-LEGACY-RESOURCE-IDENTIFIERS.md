# Retire legacy OAuth resource identifiers
1. Completed. Gather current caller, manifest and token evidence for Endpoints and Background.
2. Completed. Remove the obsolete compatibility paths and validate the modern and legacy cases in both repositories.
3. Completed. Validate and push the source changes, then record the production packaging findings.
4. Pending. Produce a release that preserves the installed runtime dependencies or obtain approval for a broader release. Verify the modern authentication paths after production rollout.

## Evidence

- On 23 November 2026 Identity had no enabled registration for either legacy
  client. The current Provisioning ID had recorded 20 token issues that UTC day.
  The live background.jobs scope declared only the sufficit-background audience,
  and no application permission referenced the retired Background scope.
  The active Background configuration files and process environment on Eveo
  had no legacy scope or audience values.
- Endpoints main: `81b88a3`. The legacy client ID lost the dedicated-client
  authorization path. The existing entitlements and directives scope rules
  remain available to the current client. Passed 283 targeted runtime tests
  and eight Markdown coverage tests in a clean checkout. The shared checkout
  had an unrelated, unreachable, untracked SIP rollout plan.
- Background main: `0cff619`. Background accepts its configured audience
  and background.jobs. The manifest now matches the live Identity scope.
  Passed 49 Release tests, the Packing build and local Release publish.
  The tests cover the default and API policies and JWT audience validation.
- Production still needs rollout. The local Background package differs from
  the installed package in 28 DLL hashes including EFData, Base and RabbitMQ.
  The live Endpoints builds predate two other commits in the proposed main
  release, which change customer finance consent and follow-up reads.
  Apoint remains a manual Endpoints deployment target.
