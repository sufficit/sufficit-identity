# Deployment build repair

Date: 2026-11-06 (America/Sao_Paulo).
Parent: [production gates](../plans/PLAN-PRODUCTION-GATES.md).

The committed impersonation change ba24c11 failed CI with three CS8601 errors
when assigning results of `Truncate` to required audit strings. The helper already
preserves non-null input; added a return `NotNullIfNotNull` annotation to express
that contract without changing runtime behavior.

Release build with warnings treated as errors and ImpersonationTests plus
MarkdownCoverageTests: **18 passed**. Full pre-deployment regression validation
is tracked in the active deployment checkpoint.

Before deployment, all three apps nodes were verified active/Healthy at
206fbb94d331c3ff37c50ddcb591593fdca8d954, with matching certificate/JWKS hashes.
No schema/mapping diff from that revision. Parallel package-lock edits remain
untouched and outside this repair. This record is not deployment evidence.
