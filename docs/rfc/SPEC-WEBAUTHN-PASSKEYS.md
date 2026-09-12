# WebAuthn Level 2 / FIDO2 — passkeys

| | |
|---|---|
| Papel | Relying Party |
| Abrangência | **B — Substancial** |
| Origem | ASP.NET Core Identity 10 (nativo), com serviço e UI próprios |
| Spec | https://www.w3.org/TR/webauthn-2/ |

## Base

Não há biblioteca FIDO2 de terceiros. O suporte é o **nativo do .NET 10**: o
`AppDbContext` declara o nono argumento genérico `IdentityUserPasskey<string>`,
o que faz `AddEntityFrameworkStores` registrar `IUserPasskeyStore` e habilita em
`UserManager` os métodos `AddOrUpdatePasskeyAsync`, `GetPasskeysAsync`,
`RemovePasskeyAsync` e `FindByPasskeyIdAsync`, e em `SignInManager` o
`CheckPasskeySignIn` (`src/sts/ServiceCollectionExtensions.cs:487-497`).

A tabela é `userpasskeys` (`src/core/Data/Mapping/PasskeyMapping.cs`).

## Configuração

| Chave | Efeito |
|---|---|
| `Passkeys:RelyingPartyId` | Vira `IdentityPasskeyOptions.ServerDomain` (`:438-444`) |
| `Passkeys:MaximumCredentialsPerAccount` | Padrão 10 |
| `Passkeys:MaximumNameLength` | Padrão 100 |
| `Passkeys:MaximumCredentialPayloadBytes` | Padrão 131 072 |

Os limites são verificados antes da atestação
(`src/sts/AspNetCoreIdentityPasskeyService.cs:69`, `:118`), o que impede um
usuário autenticado de inflar a tabela.

## Ceremônia

| Etapa | Endpoint |
|---|---|
| Opções de criação | `POST /connect/…/creation-options` — exige autenticação |
| Registro | `POST …/register` — exige autenticação |
| Opções de requisição | `POST …/request-options` — anônimo |
| Autenticação | `POST …/authenticate` — anônimo |

`src/sts/Controllers/AccountPasskeysController.cs:23-97`. A validação de origem,
de `RP ID` e do desafio é do framework.

## Estado da ceremônia fora do cookie

O ASP.NET Identity guarda o desafio WebAuthn no esquema temporário
`TwoFactorUserId`. Mantê-lo no cookie produz cabeçalho de resposta maior que o
buffer padrão de vários proxies reversos. Por isso o ticket protegido é guardado
no servidor e o navegador recebe apenas uma chave de busca aleatória
(`PasskeyAuthenticationTicketStore`, registrado em
`src/sts/ServiceCollectionExtensions.cs:447-462`).

## Integração com o resto

- Passkey verificada conta como MFA nas políticas de step-up.
- Registro e remoção emitem CAEP `device-change` e `credential-change`
  (`AspNetCoreIdentityPasskeyService.cs:202`).
- Mutação de passkey passa pelo `CredentialMutationSecurityCoordinator`, que
  rotaciona o security stamp e revoga sessões.

## Lacunas

- Sem verificação de atestação com metadados da FIDO MDS: o atestado é aceito sem
  conferir o modelo do autenticador contra uma lista.
- Sem política de exigir autenticadores com verificação de usuário obrigatória.
- Sem *conditional UI* / autofill documentada como contrato.

## Testes

`AccountPasskeyServiceTests`, `AccountPasskeysControllerTests`,
`CredentialMutationSecurityTests`.
