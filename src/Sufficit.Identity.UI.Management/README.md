# Sufficit Identity UI Management

Módulo administrativo Blazor Server injetado no composition host
`sufficit-identity`, assim como `Sufficit.Identity.UI`. Este projeto é uma
Razor Class Library: não possui processo, porta, health check, proxy ou
configuração OIDC próprios.

## Estado

Implementado:

- shell administrativo responsivo e acessível;
- rotas de visão geral, clientes, usuários, acesso, branding,
  provisionamento, auditoria e configurações;
- incorporação em `/management` no mesmo processo e origem do Identity;
- autenticação pela sessão ASP.NET Identity já emitida pelo host;
- policy de entrada para `administrator` ou `manager`;
- policies de clientes e auditoria avaliadas pelas mesmas capabilities da
  camada de aplicação;
- listagem, detalhe, criação e exclusão de clientes pelo mesmo serviço de
  aplicação usado pela API, sem uma chamada HTTP ao próprio host;
- listagem, criação, edição, prévia, ativação exclusiva e exclusão de temas de
  branding pelo mesmo serviço de aplicação usado pela API;
- acesso, pesquisa paginada, detalhe, criação contextual, atualização de
  perfil, reset de senha e bloqueio/desbloqueio de usuários pelo mesmo serviço
  de aplicação usado pela API;
- `Administrator` global e `Manager` limitado aos contextos calculados a partir
  de claims `directive` escalares ou em array no adaptador Sufficit;
- criação sem autoridade implícita, usando associação explícita ao contexto, e
  reset de senha permitido a Manager somente quando todos os contextos da conta
  estão dentro de sua autoridade;
- bloqueio com confirmação explícita, prevenção de autobloqueio, atualização do
  security stamp e revogação de tokens/autorizações; desbloqueio não restaura
  sessões anteriores;
- atualização de nome, e-mail e telefone com validação no servidor,
  confirmação reiniciada para contatos alterados, rotação do security stamp e
  revogação apenas dos tokens ativos, preservando autorizações duráveis;
- política MFA substituível e configurável por contexto;
- defaults seguros para consentimento, HTTPS, PKCE e PAR;
- confirmação explícita antes da exclusão;
- auditoria persistente de mutações e tentativas negadas, com consulta
  administrativa e redação de segredos;
- estados de loading, erro, vazio, pesquisa e tabela responsiva;
- ativos estáticos servidos como conteúdo do RCL.

Ainda não implementado:

- exclusão de usuários;
- delegação administrativa de papéis, claims e diretivas;
- títulos amigáveis dos contextos e fonte externa de políticas MFA;
- contratos administrativos de scopes isolados, sessões e grants.

## Composição no host

O composition host registra o backend e a UI quando
`Sufficit:Identity:Management:Enabled=true`:

```csharp
builder.Services.AddSufficitIdentityManagement(builder.Configuration);
builder.Services.AddSufficitIdentityManagementUI(builder.Configuration);

app.UseAuthentication();
app.UseAuthorization();
app.UseSufficitIdentityManagementEndpoints(builder.Configuration);
app.UseSufficitIdentityManagementUI();
app.UseSufficitIdentityUI();
```

A interface e a API compartilham a mesma fonte de verdade na camada de
aplicação:

```text
Navegador
   │ cookie ASP.NET Identity do host
   ▼
/management (Razor Components)
   │ DI + cookie ASP.NET Identity
   ▼
IClientManagementService / IBrandingManagementService / IUserManagementService
   ▼
OpenIddict / ASP.NET Identity

Automação externa
   │ bearer token + escopo administrativo
   ▼
/api/* (Management REST API)
   │ contratos de clientes, branding e usuários
   ▼
OpenIddict / ASP.NET Identity
```

Não deve ser registrado um cliente OIDC para a Management UI falar com o
próprio Identity host. O navegador não recebe access ou refresh tokens para
operar a interface incorporada.

## Configuração

```json
{
  "Sufficit": {
    "Identity": {
      "Management": {
        "Enabled": true,
        "RequireMfa": false,
        "Authorization": {
          "AdministratorRoles": [ "administrator" ],
          "ManagerRoles": [ "manager" ],
          "Contexts": {
            "4082aef4-42d3-4b1b-a321-f405af935940": {
              "RequireMfa": true
            }
          }
        }
      },
      "ManagementUI": {
        "PathBase": "management",
        "Authorization": {
          "ManagerRoles": [ "manager" ]
        }
      }
    }
  }
}
```

`PathBase` deve ser uma rota não raiz. O papel administrativo vem da
configuração compartilhada do Management; a UI mantém apenas os papéis que
podem entrar no shell antes das futuras capabilities contextuais. No adaptador
Sufficit, `administrator` herda
todas as capacidades de `manager` com escopo global e adiciona capacidades
administrativas.

## Limites de dependência

O RCL referencia contratos de aplicação de `Sufficit.Identity.Management` e
pode resolvê-los por DI. Ele não abre conexões, não referencia o composition
host e não cria `UserManager`/`SignInManager` ou gerenciadores do OpenIddict.

Cada operação abre um escopo DI curto e chama exatamente o mesmo use case
utilizado pelo controller da API. Validação, autorização por recurso, defaults
e auditoria pertencem a essa implementação compartilhada, nunca à página.

As páginas aplicam policies para a experiência do operador. Os controllers
REST continuam aplicando autorização própria, e os serviços de aplicação não
devem ser expostos por um transporte sem uma policy correspondente.

## Desenvolvimento e validação

O módulo não roda com `dotnet run`. Compile a biblioteca ou execute o host:

```bash
dotnet build src/Sufficit.Identity.UI.Management/Sufficit.Identity.UI.Management.csproj \
  --configuration Release

cd /caminho/para/sufficit-identity
dotnet run --project src/server/Sufficit.Identity.Server.csproj
```

Para abrir `/management/`, o host precisa de banco/configuração válidos,
Management habilitado e um usuário autenticado com um dos papéis configurados.

## Documentos

- [`PRODUCT.md`](PRODUCT.md) — propósito, usuários e limites do módulo.
- [`DESIGN.md`](DESIGN.md) — sistema visual administrativo.
- [`../../docs/single-source-ui-architecture.md`](../../docs/single-source-ui-architecture.md)
  — fronteira canônica entre UI, use cases e API.
- [`../../docs/management-authorization-architecture.md`](../../docs/management-authorization-architecture.md)
  — modelo genérico, adaptador Sufficit, fases e critérios de aceite.
- [`.impeccable/surfaces/components-pages-clients-razor.md`](.impeccable/surfaces/components-pages-clients-razor.md)
  — contrato da fatia de clientes.

## Próximas entregas

1. Implementar limites de delegação de papéis, claims e diretivas.
2. Implementar exclusão de usuários.
3. Resolver títulos de contextos e políticas MFA por uma fonte substituível.
4. Migrar provisionamento, scopes e sessões para use cases compartilhados.
