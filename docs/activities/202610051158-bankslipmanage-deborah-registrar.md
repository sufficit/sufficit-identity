# Entitlement `bankslipmanage` para a Deborah (Registrar do web)

Decisão do dono (05/10, 11h58 BRT): no sufficit-web as roles são computadas a
partir dos entitlements; o caminho correto para dar acesso a
`/Financeiro/Registrar` à equipe financeira é conceder o entitlement que
materializa `FinancialManagerRole`, não criar role na tabela `roles`.

## Contexto

- `deborah@example.com` (id `85573772-16bc-4427-82c1-372af46fad1d`)
  recebia 403 na página desde `867c6336` (sufficit-web, 29/09), que exigia
  somente `administrator`.
- Fix do site (commits `bc1d2972`/`e0c5615d`, em produção no build
  `1.26.1005.1327`): `SWCAccess` aceita `administrator` OU `financialmanager`.
- `FinancialManagerRole` (UniqueID `1ef82b4a532e4225b3db7619c5cd8870`) só se
  materializa em `UserPrincipal.Populate` via entitlements `bankslip*`
  (`bankslipmanage`/`bankslipsettings`/`bankslippayerdata`/`bankslipretention`).
  A tabela `roles` não contém `financialmanager`, e um claim de nome
  `financialmanager` seria ignorado pelo Populate (só administrator/manager são
  mapeados por nome). Ninguém tinha `bankslip*` antes desta concessão.

## Alteração (dados, não código)

INSERT direto no MariaDB `identity` (db-node-1, nó primário do Galera):

- `userclaims` id **24923**: userid `85573772-...fad1d`, claimtype
  `entitlements`, claimvalue `bankslipmanage:00000000000000000000000000000000`
  (contexto global), no mesmo formato das 15 linhas irmãs dela
  (`bankbillet`, `payment`, `balanceview` etc., todas → `FinancialRole`).

Replicação verificada: `wsrep_local_state=4` (Synced), cluster `Primary`, e o
claim id 24923 legível no db-node-3 logo após. Sem warnings no INSERT.

## Limites

- INSERT direto não gera registro em `managementauditevents`; esta activity é a
  trilha da operação. Próximas concessões preferir a API/painel de gestão.
- A usuária precisa encerrar a sessão e logar de novo para o token novo
  carregar o entitlement; só então `UserPrincipal.Populate` materializa a role
  `financialmanager` e o `SWCAccess` de `/Financeiro/Registrar` aceita.
- O entitlement é real ("gerenciar boletos"): outros produtos que leiam
  `bankslipmanage` passam a considerá-la gerente de boletos — alinhado com a
  decisão de negócio dela como gerente financeira.
