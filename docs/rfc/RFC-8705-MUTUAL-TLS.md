# RFC 8705 — Mutual-TLS client authentication e access tokens vinculados

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **B — Substancial** |
| Origem | Misto: OpenIddict 7.x nativo, mais política e encaminhamento próprios |
| Spec | https://www.rfc-editor.org/rfc/rfc8705 |

## Ativação

Tudo depende de `Sufficit:Identity:Mtls:Enabled`. Quando ligado
(`src/sts/OpenIddictServerConfiguration.cs:64-131`):

- Os **aliases** `/connect/{token,introspect,revocation,deviceauthorization,userinfo,par}/mtls`
  são registrados como endpoints reais, não só publicados em metadata — registrar
  o alias no documento sem mapear a rota não autentica ninguém (`:71-88`).
- `EnableSelfSignedTlsClientAuthentication()` habilita `self_signed_tls_client_auth` (§2.2).
- `EnablePublicKeyInfrastructureTlsClientAuthentication(...)` habilita
  `tls_client_auth` (§2.1) quando há CAs confiáveis carregadas por
  `MtlsCertificateAuthorityLoader` (`:96-104`).
- `UseClientCertificateBoundAccessTokens()` faz o OpenIddict emitir e validar o
  `cnf.x5t#S256` (§3), inclusive na introspecção (`:107-108`).
- Os aliases absolutos são publicados em `mtls_endpoint_aliases` a partir de
  `Mtls:EndpointBaseUrl`, permitindo isolar o handshake de certificado numa porta
  dedicada sem mexer no `issuer` (`:110-130`).

## Terminação no proxy

O host **não** configura Kestrel para exigir certificado; isso é deliberado e
documentado no próprio `Program.cs:440-464`. O caminho suportado em produção é a
terminação no nginx/Envoy com encaminhamento do certificado validado por
cabeçalho.

`MtlsClientCertificateForwarding` (`src/sts/Mtls/MtlsClientCertificateForwarding.cs`)
roda **antes** do middleware de proxies confiáveis (`Program.cs:471`), porque
precisa ver o IP real do peer imediato. Ele:

- **remove** o cabeçalho configurado em qualquer modo, para que um cliente não o
  injete;
- só projeta o certificado quando o peer está numa das CIDRs dedicadas de
  `Mtls:TrustedProxyNetworks`.

A validação de startup exige atestação explícita do modo de implantação:
`DeploymentMode=Unattested` é recusado, e `TrustedProxy` sem CIDR também
(`src/sts/ServiceCollectionExtensions.Validation.cs:75-120`).

## Vínculo e conflito com DPoP

`RejectCombinedDpopAndMtlsSenderConstraints`
(`src/sts/OpenIddictServerConfiguration.cs:342-346`) recusa requisição que tente
usar os dois mecanismos de posse ao mesmo tempo. Sem isso, a semântica de qual
`cnf` prevalece ficaria indefinida.

`MtlsClientCertificatePolicy` (`src/sts/Mtls/MtlsClientCertificatePolicy.cs`)
verifica o thumbprint contra a lista registrada por cliente (`:124-131`) e trata
revogação com timeout limitado (1 a 30 s, validado no startup).

## Requisitos

| Requisito | § | Estado |
|---|---|---|
| `tls_client_auth` | 2.1 | Sim, com CAs configuradas |
| `self_signed_tls_client_auth` | 2.2 | Sim |
| `cnf.x5t#S256` no access token | 3.1 | Sim (OpenIddict) |
| Validação do vínculo no resource server | 3.2 | Parcial: exposto na introspecção; a checagem é do RS |
| `mtls_endpoint_aliases` em discovery | 5 | Sim |
| Verificação de revogação | — | Sim, com timeout limitado |

## Lacunas

- Sem receita testada de Kestrel direto; o modo suportado pressupõe proxy.
- A conferência do `cnf` na chamada ao recurso depende de cada resource server.

## Testes

`MtlsPolicyTests`, `SenderConstraintTests`, `ClientsControllerTests.Credentials.Mtls`,
`DeploymentTopologyTests`.
