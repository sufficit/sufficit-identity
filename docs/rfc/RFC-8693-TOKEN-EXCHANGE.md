# RFC 8693 — OAuth 2.0 Token Exchange

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **C — Parcial** |
| Origem | Misto: grant do OpenIddict, semântica própria |
| Spec | https://www.rfc-editor.org/rfc/rfc8693 |

## Como está implementado

Grant habilitado em `src/sts/OpenIddictServerConfiguration.cs:247`
(`AllowTokenExchangeFlow`); a lógica está em `TokenExchangeGrantHandler`
(`src/sts/Grants/TokenGrants.cs`).

Quatro camadas de controle, nesta ordem:

1. **Permissão por cliente** — `Permissions.GrantTypes.TokenExchange` no
   registro, verificada pelo pipeline do OpenIddict antes do handler rodar.
2. **Kill switch** — `Sufficit:Identity:TokenExchange:Enabled` (padrão `true`).
3. **Allow-list de clientes** — `AllowedClientIds`, vazia por padrão.
4. **Política de proveniência** — `ISubjectTokenProvenancePolicy`.

## Defesa contra *confused deputy*

É o ponto mais forte da implementação. A política exige que o `subject_token`
tenha um **parte autorizada inequívoca** (`azp`/`client_id`/apresentador) e,
havendo allow-list, que essa parte pertença a ela. A verificação roda em
**toda** troca, não apenas quando a allow-list está configurada — comportamento
anterior que deixava o deployment padrão sem defesa nenhuma.

O modo `Observe` existe como escape migratório e é **reportado pelo
`ProductionPostureCheck`**, ou seja, subir em produção nesse modo exige
reconhecimento explícito (`src/sts/Security/StsProductionPostureContributor.cs:56-69`).

## Atenuação

| Dimensão | Regra |
|---|---|
| Escopos | Interseção entre o pedido e os do `subject_token`; sem pedido, herda todos. |
| Recursos | `invalid_target` se o recurso pedido não estiver autorizado pelo subject token; o resultado é a interseção. |
| Cadeia de atores | `act` é **aninhado**, preservando a cadeia anterior em vez de sobrescrevê-la (§4.1). |
| Estado do usuário | `CanSignInAsync` revalidado; conta desativada invalida a troca. |

## Requisitos

| Requisito | § | Estado |
|---|---|---|
| `subject_token` e `subject_token_type` | 2.1 | Sim |
| `actor_token` / `actor_token_type` | 2.1 | **Não lido** |
| `requested_token_type` | 2.1 | **Não tratado**; sempre emite access token |
| `issued_token_type` na resposta | 2.2.1 | Herdado do OpenIddict |
| Claim `act` com aninhamento | 4.1 | Sim |
| `may_act` | 4.4 | Não |
| `invalid_target` | 2.2.2 | Sim |

## Lacuna principal

O `subject_token` precisa identificar um **usuário**: se `sub` não resolve para
uma conta, a troca é recusada. Isso impede:

- agente ou serviço com identidade própria trocar seu token por um token de
  recurso downstream (delegação serviço-a-serviço);
- cadeias de ator sem usuário no início;
- o padrão *Cross-App Access* / ID-JAG, hoje o caminho de consenso para acesso
  de agentes entre aplicações SaaS.

A correção de projeto proposta é extrair `ISubjectTokenResolver` com duas
implementações (usuário e cliente) e ler `actor_token`.

## Testes

`TokenExchangeTests`, `TokenExchangeConfusedDeputyTests`,
`ResourceIndicatorTests`.
