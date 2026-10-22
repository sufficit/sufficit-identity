# Contas de serviço sem usuário (A5)

**22/10/2026.** Fecha o A5 de `PLAN-IDENTITY.md`.

## Consumidor que pedia userinfo com token de cliente

`sufficit-blazor-ai-bridge` chamava `/connect/userinfo` cerca de 18 vezes a
cada 10 minutos, sempre com 401 desde `46dec5e`. Quem chamava não era o
Blazor, e sim o sufficit-ai: ao validar o token de referência da ponte, a
hidratação de claims pedia o userinfo de um token que não tem usuário.

Correção no consumidor, sufficit-ai `5aad7df4`: `IsClientOnlyPrincipal` (sem
`sub`, ou `sub` igual a `client_id`/`azp`/`oi_prst`) encerra a hidratação
antes do userinfo. Publicado nos três nós do AI em 22/10; desde então, nenhuma
chamada da ponte ao userinfo nos três nós do Identity. O Identity não mudou:
continua respondendo 401 a quem pede userinfo sem usuário.

## Revisão das contas `client_credentials`

Uso pela tabela agregada (`identityapplicationusagedaily`, desde 07/08).

| Conta | Uso (7 dias) | Decisão |
|-------|-------------:|---------|
| `ec813c55-…` (fleet-credentials) | 230 | Serviço: leitor do cofre e gestor de usuários de sistema do Fleet. |
| `sufficit-blazor-ai-bridge` | 218 | Serviço: ponte servidor-a-servidor do Blazor ao AI. |
| `sufficit_provisioning_credentials` | 156 | Serviço: resolvedor de credenciais do provisionamento. |
| `sufficit-telephony-billing` | 143 | Serviço: tarifação. |
| `sufficit_ai_vault` | 113 | Serviço: leitor do cofre do AI. |
| `vestigium-sufficit` | 9 | Serviço: tenant do Vestigium. |
| `sufficit-endpoints-vault-v3` | 4 | Serviço: leitor do cofre dos endpoints. |

Nenhuma conta ativa age em nome de alguém: todas são infraestrutura entre
servidores e continuam como serviço puro. Usuário de sistema é para quem
precisa de identidade própria, como os agentes do Fleet.

### Sem uso há mais de 7 dias (remoção depende do dono)

| Conta | Último uso |
|-------|-----------|
| `API User Token Manager` | nunca (desde 07/08) |
| `SufficitEndPoints` | nunca |
| `sufficit_blazor_ai_bridge` (duplicata com `_`) | nunca |
| `sufficit-n8n-asaas-invoices` | 15/08 |
| `openclaw` | 02/09 |
| `sufficit-endpoints-vault`, `-v2` (substituídas pela v3) | 04/09 |
| `sufficit_cloud_mobile_api` | 09/09 |
| `sufficit-hermes-n8n` | 13/10 |
