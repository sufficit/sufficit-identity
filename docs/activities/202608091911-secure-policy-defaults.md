# Políticas sensíveis — defaults seguros

> **Status:** COMPLETED em 2026-08-09. Entrega de código correspondente à
> parcela local do P0.2 do plano de postura de produção.

## Entregue

- `PublicOriginPolicyOptions.Mode` inicia em `Enforce`.
- `CredentialMutationSecurityOptions.StepUpMode` inicia em `Enforce`.
- Personal tokens, política de cliente CIBA e proveniência de token exchange
  iniciam em `Enforce`.
- As políticas Management de acesso a objetos e principais protegidos iniciam
  em `Enforce`.
- O template de configuração do servidor explicita os mesmos modos seguros e
  não depende dos defaults implícitos.
- Um teste de contrato verifica em conjunto os defaults sensíveis de STS,
  Management e SCIM, evitando regressão silenciosa para `Audit`/`Observe`.

## Compatibilidade preservada

- Os modos `Audit` e `Observe` continuam disponíveis somente para rollouts
  reconhecidos pelo production posture check e com acknowledgement estruturado
  e temporário.
- A fábrica de integração mantém overrides explícitos e documentados para os
  cenários legados que não são testes de enforcement. Eles não alteram o
  comportamento do host nem o template de produção.
- Inventário de tráfego e remoção de overrides existentes em cada ambiente são
  gates operacionais e continuam no plano ativo; esta atividade não os declara
  concluídos sem evidência externa.

## Validação

- `dotnet test src/tests/Sufficit.Identity.Tests.csproj -c Release --no-restore`
  - 563 testes aprovados, 0 warnings.
- `ProductionPostureCheckTests.Security_sensitive_policy_defaults_are_enforced`
  - STS, Management e SCIM validados explicitamente em `Enforce`.
