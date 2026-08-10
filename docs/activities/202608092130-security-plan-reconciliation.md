# Reconciliação do plano de autorização, SCIM e segredos

**Concluído em:** 2026-08-09

## Resultado

O plano foi confrontado com o código, os testes, as atividades entregues e os
planos canônicos. Itens já aplicados foram retirados do checklist; itens
parciais foram reescritos para conter somente o trabalho residual. A quantidade
de checkboxes ativos caiu de 41 para 34.

## Entregas retiradas do plano

- A fronteira de configuração `ISecretStore` e os overrides
  `SUFFICIT_SECRET_*` já atendem banco, certificados, provedores externos,
  SMTP, RabbitMQ e verificação humana sem acoplar os consumidores ao JSON local.
- `IClientDefinitionValidator` pertence a Application Abstractions e é usado
  por Management, provisioning e registro dinâmico. O piso de scopes
  reservados, transições sensíveis e `Observe | Enforce` também estão
  implementados e testados.
- `ConfigurationManagementObjectAccessPolicy` está registrada como política
  concreta; exige ID para recursos de item, avalia o contexto explícito ou
  `global`, protege principais por tier e exige claim dedicado mais MFA para
  break-glass.
- As fases de named secrets e lifecycle de chaves de assinatura do vault estão
  implementadas e documentadas no plano canônico do vault.
- Redis multi-réplica, conformance, auditoria externa, rotação de credenciais e
  migração `pt1` já possuem owner operacional no plano de prontidão de produção
  e deixaram de ser duplicados neste plano.

## Itens parciais preservados como resíduo

- A política de scope grant existente valida relações de grants/scopes, mas
  ainda não modela a autoridade do operador sobre scopes privilegiados.
- O Management ainda recebe `ClientSecret` cru no contrato HTTP; provisioning
  já usa `SecretReference`.
- O fallback `global` funciona em runtime, mas contexto/ownership ainda não é
  persistido nem aplicado a todas as coleções.
- SCIM continua com autorização por cliente/scope e filtro `eq`; políticas por
  operação, partições e AST de filtros continuam pendentes.

## Evidência

- `ClientDefinitionPolicies.cs`, `ClientManagementService`,
  `IdentityProvisioningManifestValidator` e `RegistrationController`;
- `SecretConfigurationExtensions`, `EnvironmentSecretStore` e consumidores do
  `ISecretStore`;
- `ConfigurationManagementObjectAccessPolicy`,
  `ConfigurationProtectedPrincipalAccessPolicy` e
  `ManagementApplicationAuthorizationTests`;
- atividades de configuração de segredos, hardening de segurança, namespaces
  do vault e lifecycle de signing keys.

## Validação

- o plano contém 34 checkboxes pendentes distribuídos em oito passos e nenhum
  item marcado como concluído;
- `DocumentationContractTests.Canonical_documentation_links_resolve` passou;
- o teste global de nomes permanece bloqueado somente pelo arquivo paralelo
  não versionado `docs/security/RUNBOOK-STRIX-IDENTITY-SCOPE.md`, preservado sem
  alteração nesta reconciliação.
