# Sufficit.Identity.Application.Abstractions

Implementation-neutral application contracts for Sufficit Identity user
interfaces, HTTP adapters and composition hosts.

This package contains commands, projections, results, capability descriptors
and interfaces. It does not reference the Sufficit Identity runtime, EF Core,
ASP.NET Identity, OpenIddict or either official UI.

An embedded or remote UI consumes these contracts. The composition host must
provide authorized runtime implementations; installing a UI package does not
grant database or protocol-manager access.

The supported hosting models and compatibility roadmap are documented in
`docs/plans/PLAN-PLUGGABLE-USER-INTERFACES.md` in the main repository.
