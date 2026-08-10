# FAPI 2.0, JARM and Shared Signals rollout

These capabilities ship disabled. Enabling them is a client/integration
rollout, not a declaration of OpenID Foundation certification.

## FAPI 2.0

1. Provision a confidential client with `private_key_jwt` or validated mTLS.
2. Grant the pushed-authorization endpoint permission and require PAR.
3. Confirm the client sends `response_type=code`, `redirect_uri`, PKCE S256 and,
   for DPoP, `dpop_jkt` inside the authenticated PAR request.
4. Enable DPoP (including shared replay/nonce state before multiple replicas)
   or configure certificate validation at the mTLS terminator.
5. Add only the rehearsed client id under `Fapi2:ClientIds`, enable the profile,
   and run the official FAPI conformance suite against the public TLS endpoint.

The profile globally tightens authorization-code lifetime to at most 60 seconds
and PAR `request_uri` lifetime to less than 600 seconds. The current refresh
token behavior must also be assessed against the selected FAPI ecosystem
profile before claiming conformance.

## mTLS

Escolha e configure explicitamente uma topologia antes de habilitar mTLS:

- `DirectTls`: Kestrel recebe o certificado no handshake TLS. Qualquer header
  de certificado encaminhado é removido e não participa da decisão.
- `TrustedProxy`: o proxy termina mTLS e envia PEM URL-encoded ou DER base64 em
  `Mtls:ForwardedCertificateHeader`. Cadastre o IP/CIDR do peer imediato em
  `Mtls:TrustedProxyNetworks`; esta allow-list é independente da confiança
  geral em `X-Forwarded-*`. Um header vindo de outro peer é descartado.

Mantenha `RequireValidCertificateChain=true`. O default
`RevocationMode=Online` consulta revogação com o timeout configurado e
`RevocationFailureMode=FailClosed` nega quando CRL/OCSP não responde. `Offline`
usa somente dados locais. `NoCheck` e `AllowWhenUnavailable` são decisões de
compatibilidade explícitas; esta última só tolera indisponibilidade pura e não
aceita revogação, expiração ou falha de confiança.

Vincule o SHA-256 de cada certificado ao `client_id` em
`ClientCertificateThumbprints`. Para rotacionar, publique o pin novo, valide o
novo certificado, mantenha os dois pins somente pela janela de propagação e
remova o antigo. Revogação de emergência exige remover o pin comprometido e
revogar o certificado na PKI; confirme que o novo status é negado em cada
réplica antes de encerrar o incidente.

## JARM

Set `Jarm:Enabled=true` only for clients that validate the STS signing key from
JWKS and understand one of `query.jwt`, `fragment.jwt`, `form_post.jwt` or
`jwt`. JARM is independent of FAPI 2.0. Test success and error responses,
signature rotation and clock skew before production use.

On an installed host, enable or roll back the capability explicitly:

```bash
/opt/sufficit-identity/helpers/security-rollout.sh enable-jarm
/opt/sufficit-identity/helpers/activate-release.sh --current

# rollback
/opt/sufficit-identity/helpers/security-rollout.sh disable-jarm
/opt/sufficit-identity/helpers/activate-release.sh --current
```

## JAR e chaves remotas

Clientes podem registrar um JWKS público embutido ou um `jwks_uri`. Para chave
remota, use somente HTTPS público; redirect, IP privado/special-use, user-info e
fragmento são recusados. O transporte valida também o resultado DNS antes da
conexão, portanto uma allow-list de egress externa continua recomendada, mas
não substitui essa proteção local.

Dimensione `Jar:RemoteJwksMaxBytes`, `RemoteJwksTimeoutSeconds`,
`RemoteJwksCacheSeconds`, `RemoteJwksStaleSeconds` e
`RemoteJwksMaxCacheEntries` conforme a quantidade de clientes. Durante rotação,
publique a nova chave com `kid` antes de usá-la: um `kid` desconhecido força um
refresh. Se o endpoint estiver indisponível, somente um `kid` já observado pode
usar a janela stale. Conjuntos com várias chaves exigem `kid` no request object.

Não remova a chave antiga antes do maior lifetime de request object aceito e da
janela de propagação do JWKS. Monitore falhas de refresh e valide a rotação em
staging antes de ativar o novo `kid` em produção.

## SSF/CAEP

Configure receivers through secret-backed environment variables:

```text
Sufficit__Identity__SharedSignals__Enabled=true
Sufficit__Identity__SharedSignals__Receivers__0__Id=receiver-a
Sufficit__Identity__SharedSignals__Receivers__0__Audience=https://receiver.example/events
Sufficit__Identity__SharedSignals__Receivers__0__Endpoint=https://receiver.example/push
Sufficit__Identity__SharedSignals__Receivers__0__Authorization=Bearer <secret>
```

Dynamic streams must always send a non-empty `events_requested` array. An empty
or omitted array is rejected at creation and an existing persisted empty array
matches no events. This is an intentional least-privilege policy: there is no
compatibility switch that turns an unspecified subscription into every event.
Before rollout, locate old dynamic streams with an empty event list, delete
them and recreate them with the exact event-type URIs the receiver consumes.

The subject remains backward-compatible by default: an omitted value becomes
`ALL` and generates a warning. After every receiver sends an explicit subject,
enable the stricter policy:

```text
Sufficit__Identity__SharedSignals__RequireExplicitSubject=true
```

Verify `/.well-known/ssf-configuration`, validate a signed
`session-revoked` SET against the advertised JWKS, and observe a real logout at
the receiver. Direct delivery has bounded retries but no durable outbox; add a
queue/outbox before the integration requires delivery across process restarts.
The optional SSF stream-management API is intentionally absent from discovery.
