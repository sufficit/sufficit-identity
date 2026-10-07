# Node-aware release activation

The activation helper no longer requires a template node filename. It resolves the lowercase machine name and requires that override only when the active release uses it. Mandatory production configuration, release boundaries, bootstrap, locking, atomic swap, health gate and rollback remain enforced.

A functional isolated shell fixture verifies that a missing inherited node override refuses activation without changing the live symlink, and that both a correctly configured custom node and a generic node activate. The fixture is guarded on Windows because deployment helpers run on Unix hosts. DeploymentHardeningTests: 9 passed. Full solution Release build with warnings as errors: zero warnings/errors. CI and CodeQL succeeded for eec97861399004b8c752705c06c3dc1d894b91a4.

The operator explicitly authorized main integration and production deployment. First attempt was refused before swap because an older active helper still required the example filename. The corrected, checksummed helper was installed with a retained backup before running the official cluster activator. Final release 20261007T232736Z-eec9786 is active on all three nodes, with health/ready Healthy and matching certificate/JWKS hashes. Configuration and signing material were inherited per node. Migrator ran once successfully before activation. Anonymous bodyless password-recovery POST returned 401; no real email was sent and no real user's password was changed.

This documentation follows the deployed code revision and does not require a runtime rollout.
