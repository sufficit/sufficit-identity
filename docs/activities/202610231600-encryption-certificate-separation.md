# Certificado de cifra separado do de assinatura (C2, 23/10/2026)

Até hoje os três nós usavam o mesmo `certificate.pfx` para assinar e cifrar
tokens. Agora a cifra tem certificado próprio e a separação é exigida na
partida.

## O que mudou em produção

- `certificate-encryption.pfx` (RSA-3072, SHA-1 `5B741AE3…`, válido até
  23/10/2036), gerado no eveo com o runtime .NET do servidor e a senha de cifra
  atual, copiado para `/opt/sufficit-identity/` nos três nós
  (`root:www-data 0640`, mesmo sha256 nos três).
- `appsettings.Production.json` (backup `.bak-c2-*`):
  - `EncryptionPath` = `certificate-encryption.pfx`;
  - `EncryptionPaths` = novo, `certificate.pfx`, `certificate-old.pfx` — os
    antigos só para decifrar o que já foi emitido;
  - `RequirePurposeSeparation` = `true`.
- O advisory `certificate-purpose-not-separated` sumiu da partida.
- `/opt/certtool` removido do eveo.

## Por que sem fases

O OpenIddict ordena as credenciais de cifra pela validade e escolhe a que vence
por último; o certificado novo vence depois do `certificate.pfx`, então passaria
a ser o ativo mesmo listado como secundário. Por isso arquivo e configuração
foram para os três nós antes, e os reinícios vieram em seguida (≈2 min entre o
primeiro e o último).

Os access tokens JWT por cliente/recurso saem só assinados
(`AccessTokenFormatPolicy` retira a credencial de cifra), então nenhum servidor
de recurso depende da chave de cifra.

## Verificação

- 33 refresh tokens criados antes da troca resgatados depois dela, sem erro de
  decifra nos logs dos três nós; códigos de autorização também.
- Último token válido cifrado com os certificados antigos expira em
  19/11/2026 17:39 UTC; a partir de 20/11 eles saem de `EncryptionPaths`
  (item no plano).
