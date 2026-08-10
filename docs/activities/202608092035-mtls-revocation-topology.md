# Revogação e topologia verificável de mTLS

> **Status:** COMPLETED em 2026-08-09. Entrega correspondente ao P1.4 de
> plano de autenticação mTLS.

## Resultado

- A construção da cadeia X.509 aceita política `NoCheck`, `Online` ou
  `Offline`, com timeout limitado e default `Online`.
- A indisponibilidade de CRL/OCSP falha fechada por default. A exceção explícita
  `AllowWhenUnavailable` aceita somente status puramente indisponível; nunca
  suplanta certificado revogado, expirado, não confiável ou fora do pin do
  cliente. A decisão de compatibilidade recebe reason code próprio.
- `DirectTls` preserva exclusivamente o certificado da conexão TLS e remove o
  header encaminhado para impedir spoofing.
- `TrustedProxy` limpa qualquer certificado fora da topologia atestada e só
  projeta PEM URL-encoded ou DER base64 quando o IP do peer imediato pertence
  a `Mtls:TrustedProxyNetworks`. O header é removido antes do restante do
  pipeline e payload inválido falha com HTTP 400.
- A allow-list mTLS é deliberadamente separada de `TrustedProxies`; modo proxy
  sem CIDR dedicado, header inválido, timeout fora dos limites e rede catch-all
  impedem startup.

## Operação

- `ClientCertificateThumbprints` continua vinculando cada certificado SHA-256
  ao `client_id`; dois pins permitem overlap controlado durante rotação.
- A política de forwarding executa antes de `UseForwardedHeaders`, usando o IP
  real do peer e evitando confiança no `X-Forwarded-For` apresentado.
- O template e o runbook documentam revogação, rotação, falha de responder e as
  duas topologias suportadas.

## Validação

- Testes focados P1: 60 aprovados, 0 warnings.
- Casos mTLS: pin por cliente, cadeia expirada, revogada, CRL/OCSP indisponível,
  modo de disponibilidade, mapping NoCheck/Online/Offline, header válido de
  proxy confiável, header forjado de peer não confiável, payload malformado e
  startup de proxy sem allow-list.
- Template validado com `jq empty`; `git diff --check` sem violações.
