# RFC 8414 — OAuth 2.0 Authorization Server Metadata

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **A — Completa** |
| Origem | OpenIddict, com handler próprio de complemento |
| Spec | https://www.rfc-editor.org/rfc/rfc8414 |

## Como está implementado

O documento é servido em `/.well-known/openid-configuration` pelo OpenIddict. Um
handler próprio, registrado logo após `AttachEndpoints`
(`src/sts/OpenIddictServerConfiguration.cs:497-640`), acrescenta ou corrige as
entradas que o OpenIddict não conhece.

| Metadado | Fonte | Condição |
|---|---|---|
| `issuer`, endpoints, `scopes_supported`, `claims_supported` | OpenIddict | Sempre |
| `jwks_uri` | OpenIddict | Sempre |
| `code_challenge_methods_supported` | OpenIddict | Reflete a remoção de `plain` |
| `require_pushed_authorization_requests` | OpenIddict | Segue `Par.RequireForAllClients` |
| `backchannel_logout_supported` e `_session_supported` | Próprio | Publica o valor real do dispatcher |
| `frontchannel_logout_supported` e `_session_supported` | Próprio | Idem |
| `registration_endpoint` | Próprio | Só com DCR habilitado |
| `authorization_response_iss_parameter_supported` | Próprio | Sempre `true` |
| `client_id_metadata_document_supported` | Próprio | Segue a flag de CIMD |
| `dpop_signing_alg_values_supported` | Próprio | Só com DPoP habilitado |
| `authorization_signing_alg_values_supported` | Próprio | Só com JARM habilitado |
| `authorization_encryption_alg/enc_values_supported` | Próprio | Só com JARM cifrado |
| `request_parameter_supported`, `request_object_signing_alg_values_supported` | Próprio | Só com JAR habilitado |
| Aliases mTLS (`mtls_endpoint_aliases`) | OpenIddict | Só com mTLS habilitado |

## Princípio adotado

O comentário no código declara — e o código cumpre — que **nada é anunciado sem
estar implementado e ligado**. Capacidades que antes eram publicadas
incondicionalmente foram removidas quando não havia implementação por trás
(`src/sts/OpenIddictServerConfiguration.cs:492-503`). Isso importa porque um
cliente que lê `backchannel_logout_supported: true` e não recebe `logout_token`
fica com sessão órfã.

## Issuer

`SetIssuer` só é chamado quando `Sufficit:Identity:Issuer` está configurado
(`:146-150`). Sem isso o OpenIddict deriva o `issuer` do `Host` da requisição,
o que segue um cabeçalho potencialmente forjado. **Configurar sempre em
produção.**

## Descoberta do resource server

Separadamente, `/.well-known/oauth-protected-resource` implementa o RFC 9728 —
ver [RFC-9728-PROTECTED-RESOURCE-METADATA.md](RFC-9728-PROTECTED-RESOURCE-METADATA.md).
E `/.well-known/ssf-configuration` descreve o transmissor SSF
([SPEC-SSF-CAEP-RISC.md](SPEC-SSF-CAEP-RISC.md)).

## Testes

`DiscoveryTests` — o teste fixa a presença **e a ausência** de metadados
conforme as flags, o que impede anúncio acidental.
