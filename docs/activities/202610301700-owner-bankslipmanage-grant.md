# Concessão de `bankslipmanage` global ao dono (30/10/2026)

Pedido do dono: cancelar pela API de boletos 5 boletos vencidos já substituídos por boletos posteriores
(sincronização com a planilha de cobrança, `sufficit-endpoints/docs/PLAN-BANKSLIP-SERVICE-ITEMS.md`). A API
exige a diretiva `bankslipmanage` (`BankSlipManageEntitlement`, `139e7b81…`), que o usuário não tinha (tinha
`bankbillet`).

- A API de gestão (`api/claims`) exige o escopo `identity.management`, que o cliente do login por aparelho
  (`sufficit-vscode-symposium`) não pode pedir; por isso, gravação direta autorizada pelo dono.
- `identity.userclaims`: id 41995, usuário `095132cd-…` (Hugo), `entitlements` =
  `bankslipmanage:00000000000000000000000000000000` (global). Idempotente (insere só se não existir).
- Efeito só no próximo login (entitlements entram no token emitido).
- Reverter: `DELETE FROM userclaims WHERE id=41995;` e novo login.
