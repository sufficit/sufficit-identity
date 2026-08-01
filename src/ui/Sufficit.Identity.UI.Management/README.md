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
        "RequireMfa": false,
        "Authorization": {
          "OperatorRoles": [ "identity-administrator" ],
          "CapabilityClaimTypes": [ "permission", "scope" ]
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

- [`PRODUCT.md`](PRODUCT.md)
- [`DESIGN.md`](DESIGN.md)
- [`../../../docs/ui/single-source-ui-architecture.md`](../../../docs/ui/single-source-ui-architecture.md)
- [`../../../docs/ui/management-authorization-architecture.md`](../../../docs/ui/management-authorization-architecture.md)

## Próximas entregas

1. Expandir a matriz de interoperabilidade SCIM conforme integrações reais.
