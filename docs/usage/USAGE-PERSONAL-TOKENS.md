# Tokens pessoais: escopo e autorização

O escopo canônico é `personal.tokens.manage`. Ele permite solicitar tokens próprios e não concede papel administrativo nem acesso aos tokens de outras pessoas.

O servidor anuncia o nome configurado em `Sufficit:Identity:PersonalTokens:RequiredScope` e cria o registro OpenIddict antes de aceitar tráfego. `ScopeClientIds` define quais clientes receberão a permissão OAuth correspondente, preservando suas outras permissões. A lista padrão é vazia.

Exemplo da composição Sufficit (configuração operacional, sem segredos):

```json
{
  "Sufficit": {
    "Identity": {
      "PersonalTokens": {
        "RequiredScope": "personal.tokens.manage",
        "ScopeClientIds": ["SufficitBlazorServer"]
      }
    }
  }
}
```

O Blazor solicita esse escopo na autorização OIDC. Uma sessão antiga não o adquire apenas porque o aplicativo foi atualizado: é necessária nova autorização. Tokens pessoais existentes não são revogados por essa alteração.

## Requisitos mantidos

A emissão continua limitada às permissões delegadas pelo chamador, exige evidência de MFA e autenticação recente. Os padrões são 15 minutos para a autenticação e 90 dias para o token; os valores efetivos vêm da configuração. O fato de a conta ter MFA cadastrado não comprova que a sessão apresentou o segundo fator.

O HTTP 403 retorna `error`, `reasonCode`, `reasonCodes`, `requiredPermission`, `maximumLifetimeDays`, `maximumAuthenticationAgeMinutes` e `correlationId`. O cliente traduz somente códigos conhecidos, sem exibir texto operacional arbitrário.

## Publicação

Atualizar primeiro o Identity com o novo nome e a allowlist na configuração efetiva de cada nó, depois o Blazor. O deploy rolling preserva as configurações remotas: alterar somente `deploy/local/appsettings.json` não atualiza os hosts. Conferir discovery, registro OpenIddict e permissão do cliente, e autenticar novamente pelo Blazor com MFA antes de testar a emissão. Não resolver a falta de escopo atribuindo administrador ao usuário ou desativando a política.

A configuração antiga `personal_tokens.manage` precisa ser substituída explicitamente quando estiver definida em um host. O nome antigo não é aceito como alias de autorização.
