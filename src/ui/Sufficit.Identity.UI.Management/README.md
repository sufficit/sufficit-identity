# Sufficit Identity UI Management

Módulo administrativo Blazor Server incorporado ao composition host
`sufficit-identity`, assim como `Sufficit.Identity.UI`. É uma Razor Class
Library: não possui processo, porta, health check ou cliente OIDC próprios.

## Estado

Implementado:

- shell administrativo responsivo e acessível;
- rotas de visão geral, clientes, usuários e suas claims, scopes, sessões,
  autorizações, branding, auditoria e configurações;
- incorporação em `/management` no mesmo processo e origem do Identity;
- autenticação pela sessão ASP.NET Identity já emitida pelo host;
- autorização por capabilities estáveis do provedor;
- listagem, detalhe, criação e exclusão de clientes pelo mesmo serviço usado
  pela Management API;
- listagem global, detalhe, criação, edição de perfil, reset de senha,
  bloqueio/desbloqueio e exclusão segura de contas pelo mesmo serviço usado
  pela API;
- listagem paginada por usuário, pesquisa, atribuição, edição e remoção de
  claims personalizadas, com revogação dos tokens da conta;
- listagem, criação, detalhe, edição e exclusão protegida de scopes OAuth,
  incluindo vínculo com clientes e origem declarativa;
- atualização de security stamp e revogação de tokens/sessões conforme a
  operação de segurança;
- listagem segura e revogação de credenciais persistidas pelo OpenIddict, sem
  expor payload ou referência de token;
- listagem e revogação de autorizações/consentimentos com invalidação das
  credenciais relacionadas;
- CRUD e ativação exclusiva de temas de branding;
- avatar do operador resolvido pelo mesmo `IUserAvatarUrlResolver` da UI
  pública;
- auditoria persistente de mutações e tentativas negadas;
- confirmação nominal, proteção contra autoexclusão e revogação de sessões,
  tokens e autorizações antes da exclusão permanente;
- preview e aplicação transacional de manifestos declarativos por contrato
  compartilhado, com confirmação explícita e erros estruturados;
- emissão opcional de token temporário de provisioning na própria tela, visível
  uma única vez, limitado às capabilities de preview/apply, com MFA,
  expiração curta e auditoria sem o valor secreto;
- overview canônico de ambiente, transporte HTTP, política MFA, capabilities e
  disponibilidade de módulos, compartilhado com a Management API;
- estados de loading, erro, vazio, pesquisa e composição responsiva.

Não pertencem a este módulo:

- catálogo ou hierarquia de papéis empresariais;
- diretivas e permissões específicas de aplicações;
- associações de tenant, revendedor, cliente ou departamento;
- decisão sobre o efeito de uma role, group ou entitlement.

No deployment Sufficit, essas regras permanecem em `sufficit-identity-core`,
`sufficit-blazor` e nas APIs de negócio. O host pode mapear sua autoridade
operacional para capabilities do provedor sem expor essa role como opção de
usuário.

O composition host também publica o módulo SCIM RFC 7643/7644 em `/scim/v2`
quando habilitado. Esse adaptador não pertence ao RCL visual, mas reutiliza o
mesmo ciclo de vida de conta e mantém Groups separados das roles Identity.

## Composição no host

```csharp
builder.Services.AddSufficitIdentityManagement(builder.Configuration);
builder.Services.AddSufficitIdentityManagementUI(builder.Configuration);

app.UseAuthentication();
app.UseAuthorization();
app.UseSufficitIdentityManagementEndpoints(builder.Configuration);
app.UseSufficitIdentityManagementUI();
app.UseSufficitIdentityUI();
```

A interface e a API compartilham os mesmos serviços:

```text
Management UI ─┐
               ├──> application service ──> Identity / OpenIddict
Management API ┘

Sufficit Blazor ──> identity/SCIM API ──> contas e credenciais
        └────────> Sufficit API ──> roles, diretivas e contextos
```

O RCL não abre conexões, não acessa `DbContext`, não cria `UserManager` ou
`SignInManager` e não resolve gerenciadores do OpenIddict. Cada operação abre
um escopo DI curto e chama o mesmo use case utilizado pelo controller HTTP.

## Configuração

```json
{
  "Sufficit": {
    "Identity": {
      "Management": {
        "Enabled": true,
        "RequiredScope": "identity_management",
        "RequireMfa": true,
        "Authorization": {
          "OperatorRoles": [ "identity-administrator" ],
          "CapabilityClaimTypes": [ "permission" ]
        }
      },
      "ManagementUI": {
        "PathBase": "management"
      }
    }
  }
}
```

`OperatorRoles` é uma integração do deployment para pessoas que operam o
provedor. Não é um catálogo de roles oferecido aos usuários administrados.
Tokens da Management API também podem receber capabilities exatas em claims
configurados.

### Token temporário de provisioning

O bloco aparece em `/management/provisioning` somente para um operador
autenticado que tenha `identity.provisioning.apply`; a política geral do
Management continua exigindo o scope e a evidência MFA configurados no host.
O botão emite, por padrão, 15 minutos de validade e aceita no máximo 60
minutos. O token recebe apenas `identity.management` como scope e as
capabilities `identity.provisioning.preview` e `identity.provisioning.apply`.

O valor é retornado somente na resposta de emissão e fica na memória da tela
enquanto é revelado; a camada de Management não o copia para a auditoria ou
logs. O OpenIddict mantém apenas o registro necessário do reference token para
validá-lo e fazê-lo expirar. Ocultar o valor remove a recuperação pela
interface; o token já emitido continua válido até expirar. Por isso, habilite a opção somente quando a aplicação estiver
pronta para consumo e trate o valor como um segredo operacional de curta vida:

```json
{
  "Sufficit": {
    "Identity": {
      "Management": {
        "TemporaryProvisioningToken": {
          "Enabled": true,
          "DefaultLifetimeSeconds": 900,
          "MaximumLifetimeSeconds": 3600
        }
      }
    }
  }
}
```

Não existe token `super-admin` permanente nesse fluxo. A emissão é negada a
outro token temporário e cada emissão, recusa ou falha gera evento auditável
sem armazenar o Bearer.

## Tokens temporários de Management

`/management/tokens` atende automações administrativas ocasionais que precisam
de capabilities além do provisionamento. O token é um Bearer de referência,
tem no máximo uma hora, recebe somente o scope OAuth `identity.management` e
não incorpora o papel global de administrador. O operador escolhe um subconjunto
das próprias capabilities; `identity.management.tokens.issue` e
`identity.management.tokens.revoke` nunca podem ser delegadas.

Aqui, “operador” significa somente o administrador autenticado que está usando
o Management; não é um tipo de usuário separado. O contrato público usa
`identity.management.tokens.*`. Identificadores legados são aceitos apenas na
entrada para migração e sempre são normalizados antes da emissão.

A tela aceita parâmetros de query string para preparar uma solicitação. Eles
preenchem o formulário, mas não emitem credenciais e não ignoram MFA ou
autorização. Exemplo:

```text
/management/tokens?action=issue&purpose=Atualizar%20clientes%20Hermes&lifetimeSeconds=900&capability=identity.clients.read&capability=identity.clients.update
```

Parâmetros aceitos:

- `action=issue`: identifica o fluxo de emissão;
- `purpose`: finalidade auditável, com até 120 caracteres;
- `lifetimeSeconds`: duração entre 60 segundos e o limite do ambiente;
- `capability`: pode ser repetido para cada capability;
- `capabilities`: alternativa em lista separada por vírgulas.

Valores inválidos ou capabilities indisponíveis bloqueiam a confirmação e são
mostrados ao operador. O valor emitido aparece somente uma vez; a listagem
mantém metadados para auditoria e revogação. Habilitação explícita:

```json
{
  "Sufficit": {
    "Identity": {
      "Management": {
        "TemporaryOperatorToken": {
          "Enabled": true,
          "DefaultLifetimeSeconds": 900,
          "MaximumLifetimeSeconds": 3600,
          "MaximumCapabilities": 24
        }
      }
    }
  }
}
```

## Desenvolvimento

O módulo não roda de forma independente. Compile a biblioteca ou execute o
composition host:

```bash
dotnet build src/ui/Sufficit.Identity.UI.Management/Sufficit.Identity.UI.Management.csproj \
  --configuration Release

cd /caminho/para/sufficit-identity
dotnet run --project src/server/Sufficit.Identity.Server.csproj
```

## Documentos

- [`DESIGN-MANAGEMENT-PRODUCT.md`](../../../docs/design/DESIGN-MANAGEMENT-PRODUCT.md)
- [`DESIGN-MANAGEMENT-UI.md`](../../../docs/design/DESIGN-MANAGEMENT-UI.md)
- [`../../../docs/architecture/ARCHITECTURE-SINGLE-SOURCE-UI.md`](../../../docs/architecture/ARCHITECTURE-SINGLE-SOURCE-UI.md)
- [`../../../docs/architecture/ARCHITECTURE-MANAGEMENT-AUTHORIZATION.md`](../../../docs/architecture/ARCHITECTURE-MANAGEMENT-AUTHORIZATION.md)

## Próximas entregas

1. Expandir a matriz de interoperabilidade SCIM conforme integrações reais.
