# Rollout de produção: poda de tokens OpenIddict (retention 30 dias)

Data: 2026-09-11, America/Sao_Paulo.

## Contexto

A tabela `tokens` crescia sem limite: 27.628 linhas / 139,4 MiB medidos na
avaliação de 2026-09-10 (payloads JWE como reference tokens). O OpenIddict
nunca remove entradas por conta própria — codes ficam `redeemed`, revogação é
status flip. O commit `58902d0` introduziu o `OpenIddictPruningWorker`
(varrida a cada 6h via `PruneAsync` oficial; apenas entradas já mortas;
`Sufficit:Identity:TokenPruning:RetentionDays`, default 30, `<=0` desativa)
e força o caminho transacional (`DisableBulkOperations`) em conexões reais,
evitando o `DELETE` com subquery-`LIMIT` que o MariaDB rejeita.

## Pré-condições verificadas

- CI e CodeQL verdes no `58902d0` (runs 34642803886 / 34642803731);
  suíte local 1.210 aprovados + 1 skip (NATS), 0 falhas.
- Produção partia de `bfbf7bf8…` nos três nós (rollout MFA 2026-09-10).
- Sem migrations no intervalo: head do banco já em
  `20260910131719_AddTrustedProxyConfiguration`; migrador não executado.

## Publicação

- Commit: `58902d004c440977a12c35fa4b41e6b3782ee8f0` (main).
- Publish Release net10.0 (312 arquivos); `REVISION` gravado no pacote.
- Staged deploy via `deploy.py` (staging → stop → swap atômico → start),
  um nó por vez:
  - eveo-apps: swap 17:59:04, prestart OK;
  - apoint-apps: swap 18:00:25;
  - castrum-apps: swap ~18:01.
- Somente conteúdo do pacote trocado; `appsettings.*` por máquina,
  certificados e helpers preservados (exclusões do `config.json`); backups
  `.prev` removidos após start bem-sucedido em cada nó.
- STS.dll SHA256 `5b35f97a13ae4af0af0dddd03435833239f1442aaf940e53646406ea48c8a804`
  — idêntico entre build local e produção.

## Evidência do worker em produção

- eveo-apps, 17:59:15 — `OpenIddictPruningWorker: Pruned 7559 tokens and 93
  authorizations older than 30 days.` (primeira varrida; corrida idempotente:
  apoint/castrum não encontraram mais nada para remover, como desenhado).
- Banco pós-varrida: `tokens` 51.278 linhas (majoritariamente entradas com
  menos de 30 dias, que envelhecem nas próximas varridas); `authorizations`
  252 linhas. `data_free` em `tokens` ≈ 9 MiB — `OPTIMIZE TABLE` adiado:
  custo de rebuild em multimaster vivo não compensa o retorno agora.

## Verificação

- `helpers/verify-production-cluster.sh 58902d0…`: cluster uniforme nos três
  nós — service=active, health=Healthy, ready=Healthy, NRestarts=0,
  cert `5e858b8d…` e JWKS `85d43862…` estáveis e idênticos entre nós.
- Discovery externo HTTP 200 em eveo/apoint/castrum (`:26501`).
- Logs sem erros desde 17:58 nos três nós.

## Limites

- A primeira varrida removeu apenas mortos com mais de 30 dias criados até
  2026-08-12; o restante do acúmulo sai progressivamente (varridas a cada 6h).
- `OPTIMIZE TABLE tokens` permanece como follow-up opcional de janela, para
  devolver páginas ao sistema operacional após o declínio estabilizar.
