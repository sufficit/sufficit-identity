# PLAN-20260814 — Conferência de saúde: Sufficit Identity no eveo-apps

| | |
|---|---|
| **Data** | 2026-08-14 — fase 1 (inventário), somente leitura |
| **Servidor** | eveo-apps.sufficit.com.br (LXC 2101) — produção |
| **Unidade** | `sufficit-identity.service` (ativa, `Restart=on-failure`, `LimitNOFILE=524288`, user `dotnetuser:www-data`) — drop-ins: `10-dotnet10.conf`, `20-human-verification.conf` |
| **Exposição** | socket unix `/run/sufficit-identity/identity.sock` → nginx `:26501` (https) → `identity.sufficit.com.br` |
| **Runtime** | **`/opt/dotnet-10`** (DOTNET_ROOT) · csproj: **net10.0** |
| **Dependências-chave** | Redis cluster Apps (mestre local `172.19.2.101:6379/16379`, doc `202608111530`), MySQL, vault `/etc/sufficit/identity/vault-secrets.env` |
| **Consolidado** | `sufficit-servers/eveo-apps/docs/PLAN-20260814-eveo-apps-healthcheck.md` |

## 1. Estado atual (14/08 ~16:00)

- Início atual: 14/08 11:50 · uptime ~4,5h · RSS 183 MB · 45 threads
- Units auxiliares presentes: `sufficit-identity-migrator.service` (disabled), `sufficit-identity-restart.service` (static)
- Sites legados **removidos** conforme `SERVICOS-APPS-PORTAS-DNS.md` (identity-admin 26504 e identity-api 26601 não existem mais — config.json do servidor desatualizado quanto a isso)

## 2. Sinais (evidência)

1. **48 eventos de journal em 30d** — todos os visíveis são stop/start (deploys), **sem** `Failed with result` na amostra; frequência alta na noite de 13/08 e manhã de 14/08 (iteração de deploy).
2. Exceções em arquivo: `identity.log` hoje **0** · `identity.log.1` 811 · `identity.log.2/3` 73 M/51 M (06–07/08 — eram grandes; melhorou após).
3. Logs órfãos de serviços removidos ainda em `/var/log/sufficit/`: `identityadmin.log` (283 KB, parado 06/08), `identityapi.log` (701 KB, parado 06/08).

## 3. Plano de aprofundamento (fase 2 — read-only)

- [ ] Health real: `curl --unix-socket /run/sufficit-identity/identity.sock /health` (+ variantes); nginx `:26501` 200/502.
- [ ] Redis cluster: `redis-cli cluster info` no mestre local, latência, `connected_clients`, hits/misses do cache de vault; reachability dos outros 2 masters (172.19.1.113, 172.19.3.101).
- [ ] Mapear os 48 eventos: cadência de deploy vs recorrência de problema (correlacionar com `identity.log.2/3` grandes de 06–07/08).
- [ ] Verificar `sufficit-identity-restart.service` (static — o que dispara? timer? path?).
- [ ] TFM/runtimeconfig × csproj; drift de código (data binário × git log).
- [ ] Métricas: push atual + proposta de scrape.
- [ ] P3 de documentação: remover referências a identity-admin/identity-api do config.json do servidor e logs órfãos do rsyslog/logrotate.

## 4. Riscos preliminares

- P2/P3: dependência do Redis cluster novo (11/08) — sem réplica por master (perda de master = chaves daqueles slots indisponíveis até repopulação do banco, por design); medir impacto real na latência de login/token.
- P3: cadência alta de deploys sem registro de changelog por deploy (rastreabilidade).

---
*Somente leitura — nada foi alterado. Consolidado no PLAN do servidor.*
