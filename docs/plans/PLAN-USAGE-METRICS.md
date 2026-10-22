# Plano — métricas de uso agregadas

Aberto em 22/10/2026. Estado: **implementado** (registro ao final).

## Situação atual

Cada uso de aplicação (login, troca de token, refresh…) vira **uma linha** em
`identityapplicationusageevents`: cliente, tipo de evento, endpoint, grant,
resultado e o hash do usuário.

- Coleta: o caminho de autenticação publica num canal em memória (50 mil
  posições, descarta se cheio). Um worker grava em lotes de 100 no banco.
  Autenticação nunca espera.
- Exportação: o mesmo worker reenvia cada lote ao VictoriaMetrics
  (`metrics.sufficit.com.br`, line protocol, Basic), com disjuntor.
- Retenção: 90 dias por idade (`identitymetricsconfiguration`).
- Tela de métricas do Management: agrega na consulta (total, sucesso, falha,
  aplicações distintas, série diária), período de até 366 dias.
- Produção em 22/10: ~5 mil linhas/dia, 209 mil desde agosto, **65
  combinações distintas** de cliente × evento × endpoint × grant × resultado.

## Problema

Uma linha por evento é **log de eventos**, não métrica. Para responder "quantos
usos por aplicação por dia" basta um contador. O modelo atual:

- grava no banco transacional (Galera, 3 nós) ~5 mil linhas/dia que só servem
  para serem somadas;
- duplica o que já vai ao VictoriaMetrics;
- guarda o hash do usuário por evento, dado pessoal pseudonimizado que a tela
  não usa.

Só memória também não resolve: cada nó vê parte do tráfego, deploy e restart
zeram contadores, e a tela mostra até 366 dias.

## Proposta

1. **Contadores em memória** por nó, com `System.Diagnostics.Metrics`
   (`Counter<long>` `identity.application.usage`), tags limitadas: cliente,
   tipo de evento, endpoint, grant, resultado. **Sem usuário** como tag.
2. **Exportação padrão** opcional: OpenTelemetry (OTLP) ou endpoint
   Prometheus; o VictoriaMetrics aceita os dois. Substitui o envio próprio em
   line protocol. Cada nó exporta sua série; a soma entre nós é feita na
   consulta.
3. **Agregado diário no banco** para a tela do Management funcionar sem
   VictoriaMetrics (o identity é produto genérico):
   - tabela `identityapplicationusagedaily`: dia, nó, cliente, evento,
     endpoint, grant, resultado, contagem;
   - cada nó descarrega seus contadores a cada minuto com
     `INSERT … ON DUPLICATE KEY UPDATE count = count + n`;
   - **o nó faz parte da chave**: no Galera, três nós incrementando a mesma
     linha geram conflito de certificação (deadlock na escrita). Com linhas por
     nó não há disputa; a tela soma os nós;
   - retenção por idade, como hoje (90 dias por padrão).
   - Volume estimado: 65 combinações × 3 nós × 90 dias ≈ 17 mil linhas no
     pior caso, contra ~450 mil na regra atual.
4. **Remover** `identityapplicationusageevents` depois de migrar o histórico
   para o agregado (soma por dia e combinação; nó = `legacy`).

O que se perde: o hash do usuário por evento (contagem de usuários distintos
por aplicação). A tela atual não exibe isso; se um dia for preciso, o caminho
é um contador aproximado (HyperLogLog) no TSDB, não uma linha por login.

## Análise de boas práticas

| Ponto | Prática de mercado | Esta proposta |
|-------|--------------------|---------------|
| Métrica é contador pré-agregado no processo, exportado ou coletado; evento individual é log/trace. | Modelo de dados do OpenTelemetry e da instrumentação Prometheus. O ASP.NET Core e o próprio identity já usam `Meter` (`identity.metrics.accepted`, cofre, decisões de segurança). | Segue. |
| Cardinalidade baixa nas tags; nunca id de usuário como rótulo. | Recomendação explícita do Prometheus e do OpenTelemetry. | Segue (65 combinações; usuário fora). |
| Instâncias exportam séries próprias; agregação entre instâncias na consulta. | Padrão em Prometheus/OTel (rótulo de instância, `sum by`). | Segue, inclusive no agregado do banco (nó na chave). |
| Servidores de identidade expõem métricas via padrão aberto e guardam eventos de usuário à parte, com expiração. | Keycloak: métricas em endpoint Prometheus e "event store" opcional no banco com expiração configurável. Duende IdentityServer: métricas via OpenTelemetry e eventos para sinks de log. | Métricas: OTel/Prometheus + agregado. Eventos que precisam de pessoa ficam na auditoria (`managementauditevents`), com expiração por evento (PLAN-SYSTEM-USERS, revisão de 22/10). |
| Painel embutido sem TSDB obrigatório. | Comum em produtos autocontidos; aceitável com agregado pequeno e escrita periódica. | Segue: uma escrita por minuto por nó, ~65 linhas atualizadas. |
| Minimização de dado pessoal (LGPD art. 6º, III). | Não guardar dado pessoal sem finalidade. | Remove o hash de usuário por evento. |

Conclusão: **recomendado**. A coleta em memória com exportação padrão é a
prática usual. O agregado diário no banco é um complemento pragmático para o
painel sem TSDB, e só é seguro no Galera com o nó na chave.

## Entregas

| # | Entrega |
|---|---------|
| M1 | Contador `identity.application.usage` (`Meter`) no lugar do canal + gravação por evento; exportação OTLP/Prometheus opcional, substituindo o line protocol próprio (mantém disjuntor e segredo no cofre se o push continuar). |
| M2 | Tabela `identityapplicationusagedaily` (EF + SQL canônico e aditivo) e descarga por minuto com nó na chave. |
| M3 | Tela de métricas lendo o agregado (mesma API e resposta). |
| M4 | Migração do histórico para o agregado e remoção de `identityapplicationusageevents`. |

## Registro de execução

| Entrega | Verificação |
|---------|-------------|
| M1 — `IdentityUsageCounters`: contador por dia e dimensão em memória, limite de 10 mil combinações (o client id de uma falha vem de quem chama), `Counter<long>` `identity.application.usage` no `Meter` `Sufficit.Identity.Metrics` para quem coleta via OpenTelemetry. | Testes: mil usos viram um contador; limite descarta sem bloquear e combinação conhecida segue contando; restauração após falha; o código de gravação não espera nem faz I/O. |
| M2 — `identityapplicationusagedaily` com o nó na chave única; worker descarrega a cada minuto e no desligamento; retenção por dia. | Teste no banco: dois nós no mesmo dia em linhas próprias, descargas do mesmo nó somam, falha de gravação devolve as contagens à memória. |
| M3 — tela e API leem o agregado e somam os nós (mesmo contrato). Campo "eventos por lote" saiu da tela (coluna mantida, sem uso). | Teste: visão diária soma `node-a`, `node-b` e `legacy`; consultas traduzem para MariaDB com `SUM`. |
| M4 — SQL 103 (antes do deploy) e 104 (depois): histórico vira nó `legacy`, tabela por evento e hashes de usuário saem. | Aplicado em MariaDB 10.4 sobre o esquema de produção com eventos de exemplo. |

**Exportação:** mantido o line protocol já configurado no VictoriaMetrics, agora
agregado: um ponto por combinação a cada descarga, com a contagem do período e
a tag `node`. Consultas no VictoriaMetrics passam de contar pontos para somar
valores (`sum_over_time`). O `Meter` cobre quem preferir OTLP/Prometheus sem
mudar o identity.

**Produção 22/10 (`10ac64e`):** 210.081 eventos viraram 2.195 linhas `legacy`;
os nós já gravam suas linhas próprias; tabela por evento removida.
