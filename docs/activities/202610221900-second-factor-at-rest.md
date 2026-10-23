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

## Em produção (22/10/2026)

Build `2319824` nos três nós. Antes: 71 valores em texto claro (56 chaves de
autenticador, 15 conjuntos de códigos). Às 14:27 o worker do app-node-1 cifrou os
71; app-node-2 e app-node-3 encontraram 0. Chave `user-authentication-secrets` v1
criada no cofre; nenhum erro de decifração. `TwoFactor:AcceptPlaintextSecrets`
foi para `false` nos três nós às 14:3x (reinício um a um; backup
`appsettings.Production.json.bak-twofactor-20261022`).

## Troca do segredo coordenada (fecha o C3)

Conferido: redefinir o autenticador ou desligar o 2FA já atualiza o security
stamp e revoga as outras sessões (`CredentialMutationSecurityCoordinator`); a
redefinição pelo administrador também descarta os códigos de recuperação e
exige novo cadastro. Faltava, no autoatendimento, descartar os códigos de
recuperação — o Identity os mantém quando a chave muda ou o 2FA é desligado.
Eles não serviam para nada (a reativação gera novos e, desligado, nenhum fluxo
os pede), mas ficavam guardados. Agora são descartados na redefinição e na
desativação. C3 sai do plano.
