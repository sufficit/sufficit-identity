# Genius/Fleet single sign-on — Identity #73
1. [em andamento] Implement explicit configured first-party user scope grants, bounded by client permission and scope registration; regression tests.
2. [pendente] Validate and publish isolated Identity build/configuration across the cluster.
3. [pendente] Verify Genius refresh carries Fleet audience/scope; record delivery.

Default mapping empty; production mapping only sufficit-ai-genius → fleet.api. Audience comes from scope resource sufficit_fleet. No client_credentials/token_exchange broadening, no personal-token minting, no tenant authorization changes. Canonical worktree has unrelated changes and remains untouched. Refresh adds server-approved first-party scopes, following existing MCP migration precedent. Never expose credentials in logs.
