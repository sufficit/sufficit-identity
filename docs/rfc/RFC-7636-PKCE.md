# RFC 7636 — Proof Key for Code Exchange

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **A — Completa** |
| Origem | OpenIddict, com política de exigência própria |
| Spec | https://www.rfc-editor.org/rfc/rfc7636 |

## Como está implementado

Três camadas, em `src/sts/OpenIddictServerConfiguration.cs:314-322`:

1. `server.RequireProofKeyForCodeExchange()` quando
   `Sufficit:Identity:Pkce:RequireForAllClients` — impõe PKCE a **todo** cliente
   de `authorization_code`, inclusive confidencial, o que vai além do RFC 7636
   (que só o exige de clientes públicos) e segue OAuth 2.1.
2. Remoção de `plain` da lista de métodos aceitos, salvo opt-in explícito em
   `Sufficit:Identity:Pkce:AllowPlainCodeChallengeMethod`. Sem esse opt-in,
   apenas `S256` é aceito.
3. Requisito por cliente: todo cliente criado pelo plano de management ou por
   DCR nasce com `Requirements.Features.ProofKeyForCodeExchange`
   (`src/management/Clients/ClientManagementService.Mutations.cs:241-242`,
   `src/sts/Controllers/RegistrationController.cs:149`).

| Requisito | § | Estado |
|---|---|---|
| `code_challenge` no authorize | 4.3 | Sim |
| `code_verifier` no token | 4.5 | Sim |
| Verificação `S256` | 4.6 | Sim |
| `plain` desencorajado | 7.2 | Sim, removido por padrão |
| Erro `invalid_grant` em verifier errado | 4.6 | Sim |

## Interação com FAPI 2.0 e PAR

Sob FAPI 2.0 o PKCE continua obrigatório e soma-se ao `dpop_jkt` ou ao vínculo
mTLS — ver [SPEC-FAPI-2-0.md](SPEC-FAPI-2-0.md). O `code_challenge` entra pelo
PAR quando o cliente usa `request_uri`
([RFC-9126-PAR.md](RFC-9126-PAR.md)).

## Configuração

| Chave | Padrão recomendado | Efeito |
|---|---|---|
| `Sufficit:Identity:Pkce:RequireForAllClients` | `true` | PKCE obrigatório para todos. |
| `Sufficit:Identity:Pkce:AllowPlainCodeChallengeMethod` | `false` | Mantém só `S256`. |

## Testes

`AuthorizationCodeFlowTests`, `ParLoginRoundTripTests`,
`src/tests/Infrastructure/Pkce.cs` (geração de par verifier/challenge).
