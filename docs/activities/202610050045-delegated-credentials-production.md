# Credenciais delegadas e DPoP ligados em produção

Data: 2026-10-05 (UTC). Release `20261005T003450Z-9bceed1` nos três nós
(node-a, node-b, node-c), uniforme pelo `verify-production-cluster.sh`.
Única mudança de código desde `cfb7bcc8`: credenciais delegadas (`a978654`).

## Configuração aplicada (por nó, com backup `*.bak-delegation-<ts>`)

- `/etc/sufficit/identity/hardening.env`: `Sufficit__Identity__Dpop__Enabled=true`
  (`RequireForAllClients` e `RequireNonce` seguem `false`: DPoP opcional para
  os demais clientes).
- `appsettings.Production.json`, `Sufficit:Identity:TokenExchange`:
  `Enabled=true`, `AllowedClientIds=["sufficit-ai-genius"]` (nenhum outro
  cliente ganha a troca genérica) e `DelegatedCredentials` com
  `MaxAuthAgeHours=168`, `CredentialLifetimeDays=30`, `MaxActivePerUser=10`,
  `NotifyOnIssue=true`.

O comentário do `hardening.env` ("stores are process-local", por isso DPoP
desligado) estava desatualizado para DPoP: o anti-replay é
`DatabaseDpopReplayCache` (chave primária no banco compartilhado, atômico
entre réplicas) e o nonce é protegido sem estado local. Continua valendo para
CIBA.

## Limite de login recente

O dono aprovou 30 dias (720 h) como valor inicial, ajustável. O código aceita
no máximo 168 h; ficou 168 h. O posture check avisa
(`delegated-credentials-stale-sign-in`) mas não bloqueia. Subir acima de
168 h exige mudar o teto no código.

## Incidente durante a ativação (app-node-1, ~6 min)

1. Primeira tentativa: só JSON, `MaxAuthAgeHours=720` → a partida recusou
   (teto 168 h; e `Dpop:Enabled` do JSON é sobrescrito pelo `hardening.env`).
2. A restauração do backup derrubou de novo: o backup feito com
   `shutil.copy2` perdeu o grupo (`root:root` em vez de `root:www-data`) e o
   serviço não lia o arquivo. Corrigido com `chown root:www-data`.
3. node-b e node-c atenderam o tempo todo; o endpoint público respondeu 200.

Lição: backup de configuração com `cp -a`, e conferir dono/grupo antes de
reiniciar. Mudança aplicada depois em node-c → node-b → node-a, um nó por vez
com `/health/ready`.

## Validação

- `/account/login` em Chromium real: sem erro de console, nenhuma resposta
  ≥ 400; nenhum arquivo de `wwwroot` sem leitura pública nos nós.
- Discovery: `dpop_signing_alg_values_supported` = ES256, RS256;
  token-exchange anunciado.
- Posture check: passou (apenas avisos).

## Pendente

Conceder `gt:token-exchange` e `scp:genius.executor.delegate` ao cliente
`sufficit-ai-genius` (token de operador novo).
