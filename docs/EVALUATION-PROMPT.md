# Independent evaluation prompt

Perform a complete, independent evaluation and comparison of the project at
/mnt/sufficit/sufficit-identity (OAuth 2.0/OIDC STS built in .NET, OpenIddict,
ASP.NET Core Identity, MySQL). Assume nothing going in — investigate the code
from scratch, as if seeing it for the first time.

> **HARD RULE — source of truth is the code, not the docs.** For THIS project
> (sufficit-identity), you must NOT read its own documentation (README, /docs,
> comments claiming what something does, changelogs, design notes, etc.) as a
> source of truth. Project docs may be stale, aspirational, or simply wrong,
> and relying on them would give you a false picture of the real system. Build
> your understanding exclusively by reading and reasoning over the actual
> source code — classes, configuration, migrations, tests, wiring — and form
> your own independent judgment of what the system truly does. The ONLY
> documentation you may read is for THIRD-PARTY / PUBLIC projects (competitors,
> RFCs, official docs of Keycloak, Duende, OpenIddict upstream, etc.) during
> the market comparison step. If project docs and code ever disagree, the code
> wins, full stop — and note the discrepancy as a finding.

1. RECOGNITION — map the architecture on your own: projects, dependencies,
   data flow, database schema, exposed endpoints, configuration surface. Read
   the entire source code, do not summarize based on file names alone, and do
   not read this project's own documentation to shortcut this step.

2. VULNERABILITIES — actively audit on your own: authentication and OAuth/OIDC
   flows (enabled grants, PKCE, redirect_uri, token issuance and validation,
   leaked or missing claims), secrets and certificate management,
   brute-force/lockout/rate limiting, injection, broken authorization,
   sensitive data exposure, insecure defaults, outdated dependencies or known
   CVEs, attack surface of the /connect/* endpoints. Classify each finding by
   severity with a concrete exploitation scenario.

   **For each finding (and for every architectural weakness found in step 1 or
   4), do not stop at describing the problem — propose a concrete solution when
   relevant.** A good remediation says *how* to fix it at the architecture /
   software-design level: which abstraction to introduce, which pattern to
   apply, where in the code the change lands, and what the trade-off is. Favor
   design-level fixes (introduce an interface, move a responsibility, isolate a
   boundary, add an indirection) over one-line patches. Cite the specific
   file/class the change targets so the proposal is actionable, not generic.
   If a finding is purely operational (cert renewal, env var hygiene) with no
   software-design lever, say so explicitly and keep the recommendation brief.

3. MARKET COMPARISON — research the web for the current (most recent
   possible) state of direct competitors: Keycloak, Duende IdentityServer,
   plain OpenIddict, Zitadel, Ory (Hydra/Kratos), Authentik, Authelia,
   Auth0/Okta, Microsoft Entra ID, and any other relevant player that turns up.
   Compare versions, licensing, architecture, protocol coverage, default
   security posture, and what is currently considered the "modern" baseline
   for an STS (passkeys, OAuth 2.1, FAPI 2.0, DPoP, RFC 8693 token exchange,
   SSF/CAEP, authorization for AI agents/MCP). For this step, and only for
   this step, you may read the public documentation of these third-party
   projects.

4. SCORING — give a score from 0 to 10 per dimension (security, architecture,
   code quality, protocol completeness, production readiness) and an overall
   score, with objective justification for each. Rank the project against the
   competitors researched.

   **Scoring is not the deliverable — the architecture-improvement proposals
   are.** Alongside the architecture score, include a dedicated
   "Architecture improvements" section that lists, prioritized by impact, the
   concrete software-design changes you recommend (introduce / refactor /
   extract / decouple / relocate which component, and why). This is where the
   evaluation earns its value: a number without a proposal is a complaint; a
   number with a design-level proposal is engineering feedback. If you award a
   low architecture score, the corresponding proposals must explain how to
   raise it.

5. VERDICT — direct conclusion: strengths, risks that block production use,
   and whether you would recommend adopting this software today. The verdict
   must reference the top architecture-improvement proposals from step 4 as the
   roadmap to close the gaps — i.e. "to reach a production-ready architecture,
   do X, Y, Z", not just "the architecture is weak".

Work with full autonomy: run commands, read any file in the repository,
search the web, and use parallel agents to speed up investigation and market
research. Do not ask before acting — decide and execute.

Save the result to
/mnt/sufficit/sufficit-identity/docs/evaluations/EVALUATION-<date>-<model-name>.md
(name of the model used for this evaluation in the file name). Do not commit
anything.
