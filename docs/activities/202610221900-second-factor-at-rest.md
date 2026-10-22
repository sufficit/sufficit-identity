# Segundo fator cifrado em repouso (C3)

**22/10/2026.** A chave do autenticador e os códigos de recuperação ficavam
em texto claro em `usertokens` (provedor `[AspNetUserStore]`). Quem lesse o
banco ou um backup gerava o segundo fator de qualquer conta.

## O que mudou

- `ProtectedSecretsUserStore` (STS) substitui a store do EF. `AuthenticatorKey`
  e `RecoveryCodes` passam pelo cofre (`IKeyVault`, chave
  `user-authentication-secrets`) com AAD de usuário, provedor e nome: um valor
  copiado para outra conta não decifra. Gravação falha fechada: erro do cofre
  aborta, nunca grava texto claro. O resto da store é o original.
- Leitura dupla: `v1.`/`pt1.` é decifrado; texto claro legado é lido enquanto
  `Sufficit:Identity:TwoFactor:AcceptPlaintextSecrets` for `true` (padrão).
  Desligado, texto claro é erro, nunca "sem autenticador", para ninguém
  recadastrar um fator sem MFA.
- `AuthenticationSecretMigrationWorker` roda em todo nó: 10 min após subir (mais que um deploy em sequência, já que
  um nó com build anterior leria o cifrado como chave) e
  depois de hora em hora, cifra os valores em lotes de 100 com update
  condicional ao valor lido (dois nós ou o usuário mudando ao mesmo tempo não
  perdem escrita) e registra "N encrypted in this pass, M still in plain
  text". Nenhum MFA é resetado.
- A regravação na leitura, prevista no plano, ficou com o worker: uma leitura
  não grava no banco.

## Desligar o texto claro

Quando os três nós registrarem `0 still in plain text`, definir
`TwoFactor:AcceptPlaintextSecrets=false` no `appsettings.Production.json` dos
nós e reiniciar. Volta: `true`.

## Junto

- E2: a console não mostra mais nada derivado do segredo de cliente
  (`16f56fa`; SQL 106 e 107). Lista mostra rótulo, criação e expiração.
- SCIM desligado em produção (sem cliente com escopo `scim`, sem uso);
  com o módulo desligado os endpoints davam 500 por falta da política — agora
  não são mapeados.
