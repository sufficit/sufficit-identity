# Entitlement `aiuser` no contexto Sufficit para a Nilza

Pedido do dono (30/10/2026): liberar para `nilzarjborges@gmail.com` os presets
da Sufficit no sufficit-ai, igual aos da `deborah@sufficit.com.br`.

## Contexto

- Presets Tenant/Private do sufficit-ai são visíveis por contexto dono
  (`AIContextAccess.GetUserContextIds` = contextos de `aiuser`/`aicontrol`).
- Deborah (`85573772-16bc-4427-82c1-372af46fad1d`) tem
  `aiuser:d21cfb049d37473b837c67591a26feed` (contexto Sufficit, claim 24590) e
  `aiuser:000…0` (claim 24594).
- Nilza (`d884ef24-3e85-4a8e-8fab-c9b8d7ab2a9f`) tinha só
  `aiuser:000…0` (claim 41743), que resolve para o contexto pessoal dela.

## Alteração (dados, não código)

INSERT direto no MariaDB `identity` (eveo-data, primário do Galera):

- `userclaims` id **41823**: userid `d884ef24-…2a9f`, claimtype
  `entitlements`, claimvalue `aiuser:d21cfb049d37473b837c67591a26feed`.

Cluster `Primary`, `wsrep_local_state=4` (Synced) após o INSERT.

## Limites

- INSERT direto não gera `managementauditevents`; esta activity é a trilha.
- Exige novo login da usuária para o token carregar o entitlement.
- Só consumo (`aiuser`); não dá administração de presets (`aicontrol`).
- Com dois contextos, chamadas que não informam contexto podem exigir escolha
  explícita (`ResolveConsumerContextId`), como já ocorre com a Deborah.
