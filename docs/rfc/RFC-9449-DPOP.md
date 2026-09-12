# RFC 9449 — Demonstrating Proof of Possession (DPoP)

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **B — Substancial** |
| Origem | Próprio — o OpenIddict 7.x não implementa DPoP |
| Spec | https://www.rfc-editor.org/rfc/rfc9449 |

É a extensão com mais código próprio do repositório: 37 referências à RFC em
`src/sts/Dpop/`.

## Componentes

| Arquivo | Papel |
|---|---|
| `DpopProofValidator.cs` | Validação da prova JWT |
| `DpopTokenHandlers.cs` | `AttachDpopConfirmation`, `AttachDpopTokenType`, `ExtractDpopUserInfoToken`, `ValidateDpopAccessTokenProof` |
| `DatabaseDpopReplayCache.cs` | Cache de `jti` persistido, atômico |
| `DistributedDpopReplayCache.cs` | Camada distribuída |
| `DatabaseDpopNonceStore.cs`, `DistributedDpopNonceStore.cs` | Emissão e validação de nonce |
| `DpopValidationHandlers.cs` | Lado de validação de token |

Registro em `src/sts/OpenIddictServerConfiguration.cs:334-340` e
`src/sts/ServiceCollectionExtensions.cs:778-815`.

## Validação da prova

Ordem real do código (`src/sts/Dpop/DpopProofValidator.cs`):

| # | Verificação | § |
|---|---|---|
| 1 | `typ` exatamente `dpop+jwt` | 4.2 |
| 2 | `alg` restrito a `ES256` ou `RS256`, casando com o que o discovery anuncia | 4.2 |
| 3 | Chave pública extraída do header `jwk`; assinatura verificada contra ela | 4.3 |
| 4 | `htm` igual ao método HTTP, comparação sensível a maiúsculas | 4.3 |
| 5 | `htu` igual à URL sem query nem fragmento | 4.3 |
| 6 | `iat` no máximo 60 s no futuro e dentro da janela do cache de `jti` | 4.3 |
| 7 | `exp` presente e no futuro | — |
| 8 | `jti` inédito, contra cache persistido | 4.3 |
| 9 | `ath` = base64url(SHA-256(access_token)) quando há token | 4.2 |
| 10 | `nonce` igual ao emitido, quando exigido | 8 |

O passo 6 é relevante: confiar só no cache de `jti` deixaria uma prova capturada
utilizável enquanto o cache não expirasse. A janela temporal fecha isso.

## Replay entre réplicas

O cache de `jti` **não** é em memória por padrão: `DatabaseDpopReplayCache` é
registrado como `IAtomicDpopReplayCache` e persiste em `dpopreplayentries`
(`src/sts/ServiceCollectionExtensions.cs:779-783`). Há uma implementação em
processo, mas o construtor que a usa emite aviso de que é inseguro em
multi-réplica. Com três nós compartilhando o banco, o replay é bloqueado em todos.

## Dança do nonce

Em `TokenGrantDispatcher.DispatchAsync` (`src/sts/Grants/TokenGrants.cs`), quando
`Dpop:RequireNonce`:

1. A partição do nonce é `caminho | client_id | thumbprint da chave`
   (`BuildDpopNoncePartition`). Tráfego anônimo não rotaciona o desafio de outro
   cliente.
2. Se o nonce apresentado não é válido, a prova é validada **sem** nonce; só uma
   prova criptograficamente válida recebe um nonce novo, devolvido em
   `DPoP-Nonce` com erro `use_dpop_nonce`.

## Vínculo do token

| Momento | Comportamento |
|---|---|
| Emissão | `cnf.jkt` anexado por `AttachDpopConfirmation`; `token_type` vira `DPoP` |
| Refresh | O vínculo **original** é preservado; o token não pode ser reamarrado a outra chave (`UserTokenGrantsHandler`) |
| Authorization code | Sob FAPI 2.0, `dpop_jkt` autenticado no PAR é preservado no principal do código (`AuthorizationController.cs`) |
| Userinfo | `ExtractDpopUserInfoToken` + verificação de `ath` |
| Conflito com mTLS | Recusado por `RejectCombinedDpopAndMtlsSenderConstraints` |

## Configuração

| Chave | Padrão | Efeito |
|---|---|---|
| `Dpop:Enabled` | `false` | Liga a extensão e o anúncio em discovery |
| `Dpop:RequireForAllClients` | `false` | Prova obrigatória para todos |
| `Dpop:RequireNonce` | `false` | Ativa a dança do nonce |

## Lacunas

- Sem prova obrigatória por cliente: a exigência é global ou via perfil FAPI.
- `dpop_bound_access_tokens` como metadado por cliente (§5.2) não é registrado.

## Testes

`DpopTests`, `SenderConstraintTests`, `DistributedStoreTests`,
`FapiJarmTests`.
