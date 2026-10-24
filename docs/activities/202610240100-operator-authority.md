# Autoridade de operador e auditoria da quebra de vidro (A1, 24/10/2026)

## Inventário de produção

- `FullAdministratorRoles = ["administrator"]`: 3 contas.
- `RoleCapabilities`:
  - `manager` → `users.read`, `claims.read/create/delete`: 9 contas, e usado de
    fato (claims criadas e apagadas por managers nos últimos 15 dias);
  - `mobilecloudadministrator` → segredos do Vault: 1 conta;
  - `systemusers`, `claimsreader`: mapas estreitos.
- Nenhuma claim `permission` ou `role` em `userclaims`.
- Nenhum código do Identity escreve `userroles`. Os papéis vêm do legado e só
  mudam direto no banco; a página "Regras do usuário" do sufficit-blazor só os
  mostra.

## Conclusão sobre "separar a autoridade do operador"

O risco que o item descrevia — alguém ganhar poder na console pelo mesmo canal
que dá papéis e claims a usuários comuns — já está fechado por construção:

- papéis só dão poder pelo mapa revisado em configuração, e nenhuma superfície
  do Identity atribui papéis;
- `role`, `permission`, nível de principal protegido e marcas de quebra de
  vidro são tipos reservados na API de claims;
- operator tokens só delegam um subconjunto do próprio operador, e emitir ou
  revogar token nunca é delegável;
- service principals têm lista fechada.

Em vez de uma migração, o item virou trava e documentação:

- `OperatorAuthorityContractTests`: nenhum código de produção atribui papéis
  (`AddToRoleAsync`, `UserRoles.Add`, `INSERT INTO userroles`...); só o seeding
  do host de teste.
- `permission`, `identity_principal_tier`, `identity_break_glass` e
  `identity_vault_break_glass` entraram na lista de tipos que nunca saem em
  token. Hoje já não saíam (`IncludeUnmappedClaimsInAccessTokens=false`), mas
  só por causa desse flag.
- `ARCHITECTURE-MANAGEMENT-AUTHORIZATION.md`: o parágrafo dizia que manager não
  acessa a console; corrigido para o mapa real e com a seção "Where operator
  authority comes from".

## Defeito: a quebra de vidro nunca foi auditada

Das 277 mil linhas de `managementauditevents`, nenhuma marcava quebra de
vidro. Dois motivos, em todos os caminhos (usuário inclusive):

1. `CapabilityManagementAuthorizationEvaluator` terminava com
   `return ManagementAuthorizationDecision.Allowed();`, descartando o motivo da
   política de objeto (`protected_principal_break_glass`,
   `protected_principal_observed`).
2. `ManagementAuditEventFactory` grava em `ReasonCode` o código da operação
   (`claim_deleted`...) quando o serviço passa um, e `AuthorizationOutcome` só
   tinha `allowed`/`denied`.

Correção: o avaliador devolve a decisão da política de objeto; a auditoria
grava `allowed:<motivo>` em `AuthorizationOutcome` quando a permissão tem
motivo próprio. Teste `ProtectedPrincipalBreakGlassAuditTests`: operador de
nível 1 com quebra de vidro e MFA contra uma conta de nível 9, bloqueando a
conta, apagando uma claim, revogando uma sessão e uma autorização — as quatro
linhas saem com `allowed:protected_principal_break_glass`. O teste falha sem a
correção do avaliador.
