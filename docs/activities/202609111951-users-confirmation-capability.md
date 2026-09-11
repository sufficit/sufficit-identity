# Capability de confirmação de conta

Renomeado `identity.users.resend_confirmation` para `identity.users.confirmation`,
com a constante `ManagementCapabilities.UsersConfirmation`. A árvore estava limpa
no início. Foram atualizados catálogo, serviço de usuários e auditoria, contrato
público, apresentação e recursos PT/EN, além das referências de testes.

A normalização existente de capabilities foi estendida para aceitar concessões
antigas em claims/tokens e configuração de papéis. Novos tokens emitidos pelo
Management recebem o identificador canônico. Registros de auditoria históricos e
claims já persistidas não foram reescritos. A rota de envio e os códigos de resultado
mantêm seus contratos. Consumidores de código da constante antiga devem usar
`UsersConfirmation`; as buscas nos projetos consumidores não encontraram referências.

Validação executada:

```sh
dotnet test src/tests/Sufficit.Identity.Tests.csproj -p:SufficitUseLocalSui=false --filter 'FullyQualifiedName~UsersConfirmationAuthorizationTests|FullyQualifiedName~ManagementApplicationAuthorizationTests|FullyQualifiedName~ManagementCapabilityPresentationTests|FullyQualifiedName~OperatorTokensControllerTests|FullyQualifiedName~UserManagementControllerTests' -v quiet
git diff --check
```

Resultado: 50 testes aprovados, zero avisos. Cobertura inclui autorização com o novo
nome e o legado, negação para operador somente leitura, mapeamento de papéis,
emissão de token com nome canônico, apresentação e endpoints de usuários.

Alteração publicada posteriormente; consulte o [registro do deploy](202609112001-deploy-users-confirmation.md).
Contrato permanente: [Design do Management](../design/DESIGN-MANAGEMENT-PRODUCT.md).
