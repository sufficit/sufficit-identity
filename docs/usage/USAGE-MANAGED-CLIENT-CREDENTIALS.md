# Credenciais gerenciadas de aplicações OAuth

Uma aplicação pode usar uma credencial com agendamento e expiração desde seu
primeiro segredo. O segredo autentica a aplicação no fluxo `client_credentials`;
o access token emitido tem validade própria. Um segredo válido por um ano não
produz, por isso, um access token anual.

## Cadastro

As operações exigem autenticação de gestão e as capacidades de criação/alteração
de clientes. Os exemplos são modelos: substituir os marcadores e cadastrar
previamente os escopos e recursos que a aplicação poderá solicitar.

1. Criar um registro inerte com `POST /api/clients`:

   ```json
   {
     "clientId": "<client-id>",
     "displayName": "Aplicação OAuth",
     "grantTypes": [],
     "scopes": [],
     "redirectUris": []
   }
   ```

2. Enviar `POST /api/clients/<client-id>/credentials`, usando `version` da resposta:

   ```json
   {
     "expectedClientVersion": "<version>",
     "label": "Credencial de integração",
     "generate": true,
     "expiresAtUtc": "<data-UTC-ISO-8601>"
   }
   ```

   `notBeforeUtc` permite agendamento. A expiração pode ficar até 730 dias no
   futuro. O resultado traz `oneTimeSecret` uma única vez: guardar em um cofre
   do consumidor. A aplicação passa a confidencial e a credencial é persistida
   como hash no registro gerenciado. `createdAsPrimary=false` é esperado; não
   fica uma cópia permanente no campo legado `ClientSecret` da aplicação.

3. Habilitar `client_credentials` com `PUT /api/clients/<client-id>`:

   ```json
   {
     "displayName": "Aplicação OAuth",
     "expectedVersion": "<overview.clientVersion>",
     "grantTypes": ["client_credentials"],
     "scopes": ["<resource-scope>"],
     "redirectUris": [],
     "accessTokenLifetimeMinutes": 15
   }
   ```

   Usar a versão atual retornada na criação da credencial ou recarregar o
   registro antes de alterar. Os 15 minutos são uma escolha deste exemplo;
   nenhum padrão global é modificado.

Sem datas, a primeira credencial mantém o caminho legado: segredo principal
sem validade. Adicionar uma credencial com datas a uma aplicação antiga não
invalida automaticamente seu segredo principal existente.

## Emissão e renovação

Enviar `POST /connect/token`, formulário URL-encoded:

```text
grant_type=client_credentials
client_id=<client-id>
client_secret=<segredo-do-cofre>
scope=<resource-scope>
```

O consumidor usa `Authorization: Bearer <access_token>` na API destinatária,
mantém o token em cache e solicita outro antes do fim de `expires_in`.
O fluxo não emite refresh token nem ID token. O `sub` identifica a aplicação;
ele não representa um usuário humano nem herda automaticamente suas permissões.

Claims personalizados são dados opacos para o provedor. Interpretar seu
significado e autorizar recursos é responsabilidade da aplicação consumidora.
O formato do token e a audience devem ser compatíveis com a API destinatária.

## Rotação e revogação

`GET /api/clients/<client-id>/credentials` retorna metadados sem o segredo.
Criar a substituta, atualizar o consumidor e verificar emissão antes de revogar
a anterior com `POST /api/clients/<client-id>/credentials/<credential-id>/revoke`:

```json
{
  "expectedCredentialVersion": "<credential-version>",
  "reason": "Rotação concluída"
}
```

Agendamento, expiração e revogação são verificados na autenticação da aplicação.
A revogação do segredo bloqueia novas emissões; access tokens já emitidos não
são invalidados por essa operação. A política de tokens existentes depende do
mecanismo de validação/revogação adotado pelo servidor de recursos.

## Testes locais

```bash
dotnet test src/tests/Sufficit.Identity.Tests.csproj \
  -p:SufficitUseLocalSui=false -p:TreatWarningsAsErrors=true \
  --filter FullyQualifiedName~InitialManagedCredentialTests
```

Sete casos usam SQLite em memória e autorização real. Exercitam validade,
revogação, substituição, assinatura JWT via JWKS, isolamento entre credenciais
de aplicações e negativa de alteração sem capacidade administrativa. Claims
fictícios usam o namespace `urn:example:` e não representam um domínio de negócio.
Tokens e segredos são temporários e não são publicados como credenciais de uso.
