---
version: 1
slug: "components-pages-clients-razor"
primary_target: "Components/Pages/Clients.razor"
related_targets: ["Clients/ManagementClientDataSource.cs","../../../sufficit-identity/src/management/Clients/ClientManagementService.cs","wwwroot/app.css"]
---

## Scope and mode

- Primary target: `Components/Pages/Clients.razor`
- Related targets: shared application-service contracts, authorization policy
  and responsive table styles.
- Visitor mode: Operate.

## Audience and job

An authorized administrator needs to discover which OAuth/OIDC clients exist
and distinguish a backend failure from a legitimate empty result.

The first task is read-only discovery. Creation remains visibly unavailable
until mutation auditing is implemented.

## Content and states

- Use only the canonical `IClientManagementService` result shared with the
  Management API; never query persistence or synthesize client rows.
- Show application name, `client_id`, client type and registration state.
- Distinguish loading, access denied, unavailable, empty and loaded states.
- Filtering is local, immediate and announced by the visible result count.
- Recovery retries the application request; transport configuration is not
  editable from this embedded module.

## Direction

Treat the table as an operational instrument, not a dashboard decoration. The
page opens with the task and the real contract boundary, then gives most of its
space to discovery. Desktop uses a compact table; mobile turns every row into a
labeled record without horizontal scrolling.

The memorable moment is diagnostic clarity: a failed request explains exactly
which boundary stopped the operator and offers one recovery path.

## Constraints

- Preserve the established Sufficit visual system and restrained brand red.
- Reuse the host's HttpOnly Identity cookie and never create a self-referential
  OIDC client.
- The embedded RCL may resolve the canonical application contract through a
  short DI scope. It must not resolve persistence or protocol managers.
- Do not expose exception details, secrets or complete identifiers in logs or
  transient UI.
- WCAG 2.2 AA, keyboard operation, 44 px targets and reduced motion are required.

## Unresolved decisions

- Pagination and server-side filtering depend on a future API contract.
- Client creation and deletion remain out of this read-only slice.
