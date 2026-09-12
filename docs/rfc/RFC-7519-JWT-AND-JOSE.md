# RFC 7519 e a família JOSE — JWT, JWS, JWE, JWK, JWA

| | |
|---|---|
| Papel | Emissor e verificador |
| Abrangência | **B — Substancial** |
| Origem | Misto: `Microsoft.IdentityModel` via OpenIddict, mais o cofre próprio |
| Specs | RFC 7515 (JWS), 7516 (JWE), 7517 (JWK), 7518 (JWA), 7519 (JWT) |

## Onde JWTs aparecem

| Uso | Formato | Assinado por |
|---|---|---|
| `id_token` | JWS | Chave de assinatura do OP |
| Access token self-contained | JWS (`at+jwt`) | Chave de assinatura do OP |
| Access token por referência | Opaco, não é JWT | — |
| `logout_token` (back-channel) | JWS | Credencial auxiliar |
| JARM (`response=`) | JWS, opcionalmente JWE | Credencial auxiliar |
| Security Event Token (SSF/CAEP) | JWS (`secevent+jwt`) | Credencial auxiliar |
| Prova DPoP (entrada) | JWS (`dpop+jwt`) | Chave do cliente |
| Request object JAR (entrada) | JWS | Chave do cliente |
| Client assertion (entrada) | JWS | Chave do cliente |

Os tokens internos do OpenIddict (código de autorização, refresh, device code)
são **cifrados** com o certificado de encriptação, por isso o deployment exige
`Certificates:EncryptionPath` em produção
(`src/sts/OpenIddictServerConfiguration.cs:481-489`).

## Algoritmos

| Contexto | Aceitos | Origem |
|---|---|---|
| Assinatura de tokens do OP | `RS256`, `PS256`, `ES256` | `src/vault/SigningAlgorithms.cs:18-20` |
| Prova DPoP | `ES256`, `RS256` | `src/sts/Dpop/DpopProofValidator.cs` (checagem de `alg`) |
| Request object JAR | `PS256`, `ES256` por padrão | `src/sts/Options/JarOptions.cs:30-33` |
| JWE do JARM | `RSA-OAEP-256` / `ECDH-ES+A256KW` com `A256CBC-HS512` | `src/sts/Options/JarmOptions.cs:59-74` |
| JWKS de cliente | Somente chaves públicas `RSA` e `EC`, com `kid` único | `src/management/Clients/ClientJwksPolicy.cs:135-149` |

Nenhum caminho aceita `none` nem algoritmo simétrico vindo do cliente: todas as
listas são allow-lists explícitas. Isso fecha a classe de ataque de confusão de
algoritmo descrita no RFC 8725.

## Publicação de chaves (JWK Set)

`GET /.well-known/openid-configuration/jwks`
(`src/sts/OpenIddictServerConfiguration.cs:51`). Quando o cofre gerencia as
chaves (`Vault:ManageSigningKeys`), o JWKS é reescrito por
`VaultJsonWebKeySetHandler` para publicar as chaves do cofre e **remover** a
chave efêmera de bootstrap que o OpenIddict exige na validação de opções
(`src/sts/OpenIddictServerConfiguration.cs:437-450`).

Rotação: `KeyVault.RotateKeyAsync` cria versão nova sob *lease* distribuído; as
versões antigas continuam verificando, o que dá sobreposição sem downtime
(`src/vault/KeyVault.cs`, `src/vault/KeyVault.Signing.cs`).

## Lacunas

- `typ: at+jwt` não é carimbado explicitamente no access token self-contained —
  ver [RFC-9068-JWT-ACCESS-TOKEN.md](RFC-9068-JWT-ACCESS-TOKEN.md).
- Não há suporte a algoritmos pós-quânticos; o OpenIddict 8.0 preview introduziu
  ML-DSA, ainda não adotado aqui.

## Testes

`VaultSigningAlgorithmTests`, `VaultTests.Signing`, `CertificateRotationTests`,
`DiscoveryTests`.
