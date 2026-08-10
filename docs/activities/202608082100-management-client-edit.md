# Atividade concluída — edição guiada de aplicações OAuth/OIDC

**Data:** 2026-08-08
**Projeto:** `sufficit-identity`
**Status:** concluída, testada e validada

## Entrega

- Adicionada a capability `identity.clients.update`.
- Criado `UpdateManagementClientCommand` e o endpoint
  `PUT /api/clients/{clientId}`.
- A atualização reutiliza a validação de grants, scopes, redirects e logout
  do gerenciamento de clientes.
- O `ClientId` permanece imutável e o client secret existente é preservado;
  nenhum segredo é retornado pela API ou pela UI.
- O detalhe expõe uma versão opaca para concorrência otimista. Versões antigas
  são rejeitadas sem sobrescrever alterações concorrentes.
- Aplicações identificadas como gerenciadas pelo manifesto declarativo ficam
  somente leitura e orientam o operador a editar o manifesto.
- Criada a rota `/management/clients/{id}/edit`, com três seções adequadas a
  dispositivos móveis: identidade, protocolos/scopes e URLs/logout.
- O detalhe agora oferece o botão **Editar**, estado de atualização concluída
  e indicação de origem declarativa.
- O resultado é auditado com `identity.clients.update`.

## Validação

- `dotnet build src/server/Sufficit.Identity.Server.csproj --no-restore` — OK.
- `dotnet build src/tests/Sufficit.Identity.Tests.csproj --no-restore` — OK.
- 66 testes direcionados de API, autorização, arquitetura e navegação — OK.
- Teste específico confirmou preservação do segredo e rejeição de versão
  obsoleta — OK.
- Detector visual `impeccable` executado nos arquivos da UI; os avisos
  encontrados (`Inter` e acento lateral) já pertencem ao design system
  existente, sem novo antipadrão introduzido nesta entrega.

A suíte completa ainda possui uma falha independente em
`VaultTests.Vault_managed_signing_publishes_versioned_jwks_endpoint`, fora do
escopo desta atividade.

## Próxima etapa

O plano pendente continua em
`docs/plans/PLAN-MANAGEMENT-APPLICATIONS.md`, agora somente com as lacunas
restantes do gerenciamento de aplicações.
