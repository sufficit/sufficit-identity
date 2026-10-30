# Username e e-mail empresariais para a Nilza

Pedido do dono (30/10/2026): a conta `d884ef24-3e85-4a8e-8fab-c9b8d7ab2a9f`
(antes `nilzarjborges@gmail.com`) passa a ser reconhecida como
`nilza@sufficit.com.br`. O login Google vinculado (sub
`116604281380381206331`) é a conta Google Workspace da Sufficit, confirmado
pelo dono.

## Modelo

O Identity tem um único `Email` e um único `UserName` por usuário. Não há
e-mail secundário nem alias. Formas múltiplas de entrar = métodos de login
(senha, passkeys, N logins externos em `userlogins`), vinculáveis pela própria
pessoa em `/manage/externallogins`. `name` e `preferred_username` nos tokens
vêm do `UserName`; `email` do `Email`; `sub` (id) não muda.

## Alteração (dados, não código)

Transação no MariaDB `identity` (eveo-data, primário do Galera), espelhando
`UserManagementService.UpdateProfile`, porque o admin API exige sessão admin
com MFA indisponível nesta sessão:

- `users`: `username`/`email` = `nilza@sufficit.com.br`, normalizados em
  maiúsculas, `securitystamp` e `concurrencystamp` novos (1 linha).
- `tokens`: 1115 tokens `valid` do subject → `revoked`
  (equivalente a `RevokeBySubjectAsync`).
- `emailconfirmed` mantido em 1: o Google vinculado comprova o endereço, e e-mail
  não confirmado faria o próximo login externo "reivindicar" a conta e apagar
  senha, logins externos e 2FA (`ClaimUnconfirmedAccountAsync`).

Galera `wsrep_local_state=4` após o commit. Unicidade conferida antes (nenhum
outro usuário com `NILZA@SUFFICIT.COM.BR`).

## Limites

- Sem `managementauditevents`; esta activity é a trilha.
- Cache de validade de sessão dos nós é best effort; o security stamp no banco
  é a autoridade. Access tokens JWT já emitidos valem até expirar.
- O Gmail pessoal deixou de existir na conta: recuperação de senha e avisos vão
  para `nilza@sufficit.com.br`. Senha (se houver) agora entra pelo username novo.
- Sistemas que usem e-mail/username como chave em vez de `sub` precisam ser
  verificados caso a caso.
