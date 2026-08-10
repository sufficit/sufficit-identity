# Production posture — contributors modulares e fail-closed efetivo

> **Status:** COMPLETED em 2026-08-09. Entrega correspondente ao P0.1 de
> `PLAN-CLAUDE-FABLE-5-REMAINING.md`.

## Entregue

- O contrato `IProductionPostureContributor` passou a pertencer a Application
  Abstractions; STS, Management, SCIM e Vault registram contributors próprios.
- A composição cobre CSP report-only, Management sem autorização, políticas de
  objeto/principal em Observe, SCIM sem allow-list ou em Observe, token-exchange
  provenance, personal tokens, CIBA, credential-mutation step-up, public origin,
  vault plaintext e cache DPoP incompatível com o modo compartilhado.
- O host agrega contributors via DI e rejeita IDs duplicados, impedindo colisão
  ou sobrescrita silenciosa entre módulos.
- Acknowledgements agora são individuais e exigem owner, reason e expiry futura.
  Entradas expiradas, inválidas ou sem finding ativo não liberam o startup.
- Os booleans legados de CSP/Management só são aceitos quando
  `AllowLegacyBooleanAcknowledgements=true` é configurado explicitamente e
  sempre produzem deprecation warning.
- `FailClosedOnInsecureDefaults=false` deixou de ser bypass global. Fora de
  Development, findings não reconhecidos sempre bloqueiam startup; Development
  apenas registra warnings.
- O template publica fail-closed ligado, bridge legado desligado e mapa de
  acknowledgements vazio.

## Decisões

- A configuração antiga foi preservada apenas para binding, marcada como
  obsoleta e ignorada pelo enforcement. Isso evita quebra de desserialização sem
  manter o comportamento inseguro.
- Token exchange continua vinculado à sua seção histórica, portanto o
  contributor lê a mesma configuração usada pelo controller; a extração dessa
  option para DI pode ocorrer junto da decomposição posterior do controller.
- O teste de contrato enumera todos os switches permissivos conhecidos. Um novo
  switch exige contributor e ID estável para entrar nessa matriz.

## Validação

- `dotnet build Sufficit.Identity.sln -c Release --no-restore`
  - 14 projetos, 0 erros, 0 warnings.
- `dotnet test src/tests/Sufficit.Identity.Tests.csproj -c Release --no-build`
  - 563 testes aprovados, 0 warnings.
- `ProductionPostureCheckTests`
  - 12 cenários para cobertura, acknowledgements, expiração, IDs duplicados,
    bridge legado, Development e fail-closed fora de Development.
