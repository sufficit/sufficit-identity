# Seções fechadas saem do plano (28/10/2026)

O plano passou a guardar só o que falta. Seções inteiras já entregues saíram e
deixam um vão na numeração (os ids continuam estáveis). Cada uma aponta para a
atividade que registra a entrega:

| Seção | Registro |
|---|---|
| A1 — principais protegidos e autoridade do operador | [`202610240100`](202610240100-operator-authority.md), [`202609192300`](202609192300-protected-principals-everywhere.md) |
| B1 — núcleo único de emissão (decidido: não) | [`202610240200`](202610240200-no-unified-issuance-service.md) |
| B2 — liberação de claims falha fechada | [`202610221930`](202610221930-vault-restore-proof-and-claim-inventory.md), [`202610240200`](202610240200-no-unified-issuance-service.md) |
| B7 — consentimento falha fechado | [`202610231700`](202610231700-csp-inline-styles.md) |
| B8 — validação de resource por cliente | [`202610221630`](202610221630-plan-reconciliation.md) |
| D2 — origem pública | [`202610221630`](202610221630-plan-reconciliation.md) |
| D3 — topologia explícita | abaixo |
| D4 — modos de aplicação por ambiente | abaixo |
| D5 — cache compartilhado real | [`202610241900`](202610241900-replica-rehearsal.md), [`202610281700`](202610281700-replica-revocation.md) |
| E5 — componente único de estado de resultado | [`202610240300`](202610240300-management-data-view.md) |

Itens `[x]` e parágrafos de histórico das seções que continuam abertas também
saíram; ficou uma linha "Built on" com o link da atividade.

## D3 — topologia explícita (24/10, `f8456f6`)

`TwoReplicaSmokeTests` sobe dois hosts no mesmo banco e no mesmo cache
distribuído:

- uma prova DPoP usada numa réplica é replay na outra;
- um nonce DPoP emitido por uma é aceito pela outra;
- um pedido CIBA criado numa é resgatado exatamente uma vez entre as duas;
- registro ou login de passkey iniciado numa termina na outra e não pode ser
  repetido em nenhuma.

Nenhum estado que precisa ser compartilhado vive na memória de um processo.

## D4 — inventário de modos por ambiente (24/10)

Produção é a única implantação do Identity (os três nós `*-apps`; não há
homologação). A checagem de postura passava sem nenhum achado desde os deploys
de C2, D1 e A1. Um ambiente novo precisa passar na mesma checagem antes de
receber tráfego; os padrões de código que ainda começam em `Observe` (política
de cliente CIBA, tokens pessoais, proveniência do token exchange, step-up de
mutação de credencial) aparecem nela.

Desde 28/10 a checagem traz um aviso esperado,
`management-client-scope-grants-observe`, até a A2 passar a `Enforce`.

## E6 — inspeção automática no celular (24/10, `9dc112f`)

`ManagementConsoleResponsiveTests` confere todas as páginas do console em 320,
360, 390 e 430 px e a ordem de tabulação do menu lateral. Rodada contra
produção num tablet, achou os 18 links do menu fechado ainda focáveis fora da
tela e a tabela de contas de serviço alargando a página para 425 px; os dois
foram corrigidos em `9dc112f`.
