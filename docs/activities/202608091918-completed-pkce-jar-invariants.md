# Invariantes de cliente e Request Object

> **Status:** COMPLETED em 2026-08-09. Entrega correspondente ao P0.3 de
> `PLAN-CLAUDE-FABLE-5-REMAINING.md`.

## PKCE

- `IClientDefinitionValidator` passou a projetar a exigência de PKCE a partir
  do grant `authorization_code`, sem depender do tipo público/confidencial.
- Management create/update, provisioning declarativo e DCR consomem a mesma
  decisão ao preencher `ProofKeyForCodeExchange` no descriptor OpenIddict.
- O validator rejeita qualquer cliente authorization-code cuja definição tente
  omitir PKCE.
- A matriz de contrato cobre público/confidencial com authorization-code e com
  grants que não exigem PKCE; os três entry points também possuem verificação
  da requirement persistida.

## JAR

- Depois da validação de tipo, algoritmo, assinatura, issuer, audience,
  lifetime e replay, o extrator substitui todo o conjunto de parâmetros pela
  carga assinada.
- O único dado externo preservado é o `client_id` já comparado com o JWT.
  `scope`, `resource`, `prompt`, `max_age`, `login_hint`, `acr_values` e
  extensões externas ausentes do payload são removidos.
- Claims JWT internos não viram parâmetros OAuth; carriers aninhados `request`
  e `request_uri` e nomes JSON duplicados são rejeitados.
- Objetos e arrays assinados são projetados como `JsonElement`, sem redução para
  string; os testes cobrem `claims` e `authorization_details` estruturados.
- O replay continua sendo marcado somente depois da validação criptográfica.

## Limite desta entrega

- O suporte remoto a `jwks_uri` não foi declarado concluído. Ele permanece no
  P1.3, onde será implementado com egress seguro, limites e cache controlado.

## Validação

- `dotnet build Sufficit.Identity.sln -c Release --no-restore`
  - 14 projetos, 0 erros, 0 warnings.
- `dotnet test src/tests/Sufficit.Identity.Tests.csproj -c Release --no-restore`
  - 568 testes aprovados, 1 skip esperado, 0 warnings.
