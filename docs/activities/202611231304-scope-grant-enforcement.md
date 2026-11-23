# Privileged scope grant enforcement in production

On 23 November 2026 the maintainer authorized A2.1 after reviewing the
[observed grant decisions](202611231252-november-operational-review.md).
By 13:04 São Paulo time all three application nodes had restarted with
Sufficit:Identity:Management:ClientScopeGrants:Mode set to Enforce.

The previous configuration on each node was Observe with 18 privileged scope
entries. The rollout held the cluster deployment lease and checked the live
revision, each configuration checksum and the service environment. The only
configuration difference was the mode. On each node the previous settings
were backed up in a root-only directory before atomic replacement. Each new
process passed the direct health and readiness checks before the rollout
advanced. The node-local backup is at
`/root/identity-scope-grants-20261123T1603Z/appsettings.Production.json`.
To roll back, restore the original mode on each node and restart sequentially
under the cluster lease using the active release helper and readiness checks.

Direct health probes briefly returned HTTP 502 during restart. All three
services ended active and ready on release f852e831, with consistent
certificate and JWKS digests. Public health, readiness and discovery each
returned HTTP 200. All 15 focused scope authorization tests passed, including
HTTP refusal of an unauthorized privileged grant and retention of existing
grants. Production verification used configuration, process and health checks.
The refusal itself was exercised on an isolated host.
