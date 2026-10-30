# Acesso irrestrito ao setor comercial/financeiro: Nilza e Deborah

Pedido do dono (30/10/2026): Nilza e Deborah, gestoras, devem ter acesso
irrestrito às atividades do setor comercial e financeiro, para que a migração
do sistema de serviços legado para o nativo não as bloqueie.

## Alteração (dados, não código)

INSERT direto no MariaDB `identity` (eveo-data, primário do Galera), só das
chaves que faltavam, contexto global `000…0`. Conjunto completo do setor =
todas as entitlements de `sufficit-identity-core/src/Sales` e `src/Finance`:

`clientadmin`, `customergroup`, `salesintegrationaudit`, `salesintegrationretry`,
`servicediscount`, `servicemonitor`, `serviceupdate`, `balancetransfer`,
`balanceupdate`, `balanceview`, `bankbillet`, `bankslipmanage`,
`bankslippayerdata`, `bankslipretention`, `bankslipsettings`, `expenseupdate`,
`expenseview`, `finance`, `payment`.

- Deborah (`85573772-16bc-4427-82c1-372af46fad1d`): 13 novas, `userclaims` ids 41871–41919.
- Nilza (`d884ef24-3e85-4a8e-8fab-c9b8d7ab2a9f`): 11 novas, ids 41923–41963.

Conferência: as duas com 19/19; `wsrep_local_state=4`. Ambas já tinham a role
`manager`. Roles materializadas: `salesmanager`, `salesrepresentative`,
`financial`, `financialmanager`.

## Limites

- Não concede `administrator` nem `gatewaydiagnostics` (que materializa administrator).
- INSERT direto não gera `managementauditevents`; esta activity é a trilha.
- Exige novo login das usuárias para o token carregar as entitlements.
- Script: `INSERT … SELECT … WHERE NOT EXISTS` (idempotente).
