# Genius/Fleet single sign-on — Identity #73
1. [concluído] Implement explicit configured first-party user scope grants, bounded by client permission and scope registration; regression tests.
2. [em andamento] Validate and publish isolated Identity build/configuration across the cluster.
3. [pendente] Verify Genius refresh carries Fleet audience/scope; record delivery.

Default mapping empty; production mapping only sufficit-ai-genius → fleet.api. Audience comes from scope resource sufficit_fleet. No client_credentials/token_exchange broadening, no personal-token minting, no tenant authorization changes. Canonical worktree has unrelated changes and remains untouched. Refresh adds server-approved first-party scopes, following existing MCP migration precedent. Never expose credentials in logs.

Local validation: 1355 tests passed. Legacy refresh must omit optional scope to accept issuer migration; explicitly requesting old scope narrows response. Production registration updated additively with scp:fleet.api (one client row); scope already maps exclusively to sufficit_fleet. Primary CI running in contingência linux-ci.
