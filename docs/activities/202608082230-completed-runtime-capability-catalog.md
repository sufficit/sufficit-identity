# Atividade concluída — catálogo de capacidades do runtime

**Data:** 2026-08-08
**Status:** concluída, testada e validada
**Plano:** [`../plans/PLAN-MANAGEMENT-APPLICATIONS-NEXT.md`](../plans/PLAN-MANAGEMENT-APPLICATIONS-NEXT.md)

## Entrega

- Criado o contrato compartilhado `IIdentityRuntimeCapabilityCatalog` para a
  Management UI e a Management API consultarem as capacidades do processo que
  está executando.
- O STS agora projeta grants e recursos realmente habilitados, incluindo
  Authorization Code, Client Credentials, Device Authorization, Refresh Token,
  Token Exchange e recursos opcionais como PAR, JAR, JARM, DPoP, mTLS, FAPI 2,
  CIBA, DCR e MCP.
- O módulo de gerenciamento usa um fallback fechado quando é hospedado sem o
  STS; assim a UI não oferece um fluxo que o host não consegue processar.
- Os perfis do configurador passam a informar quando estão indisponíveis e a
  criação de rascunho rejeita um perfil desabilitado no runtime.
- A apresentação dos perfis indica visualmente as opções indisponíveis,
  preservando o fluxo mobile-first.

## Validação

- `dotnet build src/tests/Sufficit.Identity.Tests.csproj --no-restore`
- `dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-build --filter "FullyQualifiedName~RuntimeCapabilityCatalogTests|FullyQualifiedName~ClientDraftsControllerTests|FullyQualifiedName~ManagementUiRoutingTests"`
- Resultado: build sem erros e 24 testes aprovados.

## Limites mantidos

Nenhum grant global foi habilitado ou alterado por esta atividade. A lista de
aplicações, a paginação no servidor e os cards mobile continuam pendentes no
plano seguinte.
