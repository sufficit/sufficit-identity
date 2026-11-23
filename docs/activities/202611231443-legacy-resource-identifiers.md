# Retirement of legacy OAuth resource identifiers
1. Completed. Gather current caller, manifest and token evidence for Endpoints and Background.
2. Completed. Remove the obsolete compatibility paths and validate the modern and legacy cases in both repositories.
3. Completed. Validate and push the source changes, then record the production packaging findings.
4. Completed. Rebuild the changed assemblies against the exact installed dependencies.
5. Completed. Roll out and verify Background on Eveo and Endpoints on Eveo and Castrum.
6. Completed. Publish the validated Endpoints candidate on Apoint with the maintainer’s approval. Verify health, DLL hashes and the current Provisioning client.

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
- The initial full Background package differed in 28 DLL hashes.
  The proposed full Endpoints release also included unrelated finance changes.
  The isolated rollout used the installed dependencies instead.

## Production verification on 23 November 2026

- Background on Eveo. All 93 DLL hashes matched the installed baseline before
  recompilation. Only the API DLL changed. Its SHA-256 is
  `57b267c8c5e2b10a9d0c61a3a9fd78b2d6e4cf9467c9a82383941060bf281299`.
  Three authorization tests passed against the exact candidate and installed
  dependencies. The public readiness route returned HTTP 200, sign-in
  redirected to Identity requesting background.jobs, and a protected API
  read without a session returned HTTP 401. An authenticated Background API
  read was exercised in the candidate policy tests only. The previous
  DLL and PDB remain in a root-only server backup.
- Endpoints on Eveo and Castrum. The installed PDB matched all 599 C# input
  checksums in c09ca74 on Eveo, and both installations matched the 176 DLL
  hashes of the same artifact. The rebuild incorporated the authorization
  change from 81b88a3 and preserved dependency versions and hashes.
  The closure check found zero missing references. The exact candidate and
  matching Base, EFData and Standard libraries passed 281 tests. After the
  standard staging and promotion procedure, only the Endpoints DLL changed.
  The installed SHA-256 is
  `f045a7537e867a06033d9ce98e1b9d03bad3cece65f9d7993d9139fa0f4d7d5e`
  on both nodes. The current Provisioning client obtained HTTP 200 from
  Identity and received HTTP 204 for the read-only lookup on each node.
  Both health checks returned Healthy and the deployment retained rollback copies.
- Apoint was healthy and its distinct baseline matched all 176 hashes of its
  own local artifact. Its 599 C# input checksums matched d8a351e. The isolated
  candidate includes the same authorization change, passed 281 tests and
  has zero missing assembly references. The Endpoints DLL SHA-256 is
  `2268674cfa0508cea167a014b4ac8fb0a5201ec7896e06a7eb8c809b3861f001`.
  The maintainer authorized the rollout. Staging, configuration preservation,
  promotion and readiness succeeded. Of the 176 verified DLL hashes, only the
  Endpoints DLL changed. All three Endpoints nodes reported Healthy.
  The current Provisioning client obtained a token with HTTP 200 and the
  read-only query on Apoint returned HTTP 204. Apoint retained rollback at
  `/opt/sufficit-endpoints.before-a3f618b08d8243ac9cbb7a8469e4349a`.
