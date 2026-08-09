# Avaliação Claude Fable 5 — plano de implementação remanescente

> **Status:** ACTIVE. Reconciliado em 2026-08-09 contra
> `52ce1f9`. Origem: avaliação interna `EVALUATION-2026-08-09-claude-fable-5.md`
> (mantida fora do versionamento após a reconciliação).
>
> Este documento contém somente trabalho ainda aplicável. Ele não incorpora a
> nota de mercado nem transforma observações informativas em bloqueadores. Onde
> já existe um plano canônico, este plano registra a dependência e o critério de
> fechamento, sem criar uma segunda implementação concorrente.
>
> Contributors modulares, acknowledgements estruturados, fail-closed efetivo,
> defaults seguros, invariantes PKCE/JAR, exclusividade DPoP/mTLS e boundaries
> fail-closed do vault foram entregues e removidos deste plano; evidências em
> [`202608091904-completed-production-posture-contributors.md`](../activities/202608091904-completed-production-posture-contributors.md)
> e
> [`202608091911-completed-secure-policy-defaults.md`](../activities/202608091911-completed-secure-policy-defaults.md)
> e
> [`202608091918-completed-pkce-jar-invariants.md`](../activities/202608091918-completed-pkce-jar-invariants.md)
> e
> [`202608091925-completed-sender-constraint-exclusivity.md`](../activities/202608091925-completed-sender-constraint-exclusivity.md)
> e
> [`202608091930-completed-vault-fail-closed-boundaries.md`](../activities/202608091930-completed-vault-fail-closed-boundaries.md)
> e
> [`202608092355-completed-vault-signing-key-lifecycle.md`](../activities/202608092355-completed-vault-signing-key-lifecycle.md).
> Autorização de named secrets por contexto/namespace foi entregue em
> [`202608092010-completed-vault-secret-namespaces.md`](../activities/202608092010-completed-vault-secret-namespaces.md).
> Resolução segura de `jwks_uri` para JAR foi entregue em
> [`202608092022-completed-jar-remote-jwks.md`](../activities/202608092022-completed-jar-remote-jwks.md).
> Revogação e topologia confiável de mTLS foram entregues em
> [`202608092035-completed-mtls-revocation-topology.md`](../activities/202608092035-completed-mtls-revocation-topology.md).

## Resultado da reconciliação

O diagnóstico central do relatório é válido: a maior lacuna atual não está na
correção criptográfica dos protocolos, mas na diferença entre controles
implementados e controles efetivamente aplicados em produção. O primeiro
objetivo é fazer o processo recusar uma postura permissiva não reconhecida; o
segundo é fechar os poucos desvios de protocolo e custódia de chaves que ainda
permitem downgrade ou confiança excessiva.

Quatro recomendações precisam de ajuste antes de serem implementadas:

1. `Observe` não será removido abruptamente de SCIM e token exchange. O STS já
   atende tráfego de produção, portanto o modo permanece durante uma janela de
   inventário, passa a exigir reconhecimento explícito e expira depois da
   migração para `Enforce`.
2. Os vários enums de enforcement não serão unificados antes dos controles.
   Primeiro será criado um contrato comum de contribuição para a postura; a
   consolidação dos tipos só ocorrerá se ainda reduzir complexidade depois do
   rollout.
3. DPoP e mTLS não terão seus membros de `cnf` apenas mesclados. Hoje o validador
   DPoP desativa a validação PoP nativa do OpenIddict; mesclar sem alterar a
   validação faria uma das duas provas deixar de ser exigida. A primeira entrega
   deve rejeitar a combinação e garantir exatamente um sender constraint.
4. O vault não será ligado sem migração dos valores `pt1`. O estado final é
   `PassThroughKeyVault` restrito a Development, alcançado por rollout e não por
   uma quebra imediata de inicialização.

## Restrições de entrega

- Preservar grants, clientes, usuários, rotas e integrações durante o rollout.
- Introduzir observabilidade e inventário antes de trocar uma decisão de
  compatibilidade por negação.
- Manter mudanças de schema aditivas e compatíveis com rolling deployment.
- Não registrar tokens, proofs, códigos, valores de segredo, chaves ou conteúdo
  de request objects.
- Toda exceção temporária de produção deve ter identificador estável,
  justificativa, responsável e expiração; um booleano genérico e permanente não
  é critério suficiente.
- Itens operacionais continuam nos runbooks e planos canônicos; este plano só os
  referencia como gate de release.

## Decisão por achado

| Achado | Decisão | Evidência atual e destino |
| --- | --- | --- |
| S3 — SCIM Observe permite cliente fora da allow-list | **Aceito com rollout, P0** | O default já é `Enforce`, mas `ScimClientHandler` concede em `Observe`. Tornar o uso temporário, reconhecido e bloqueado pelo posture check; remover após a janela de migração. |
| S4 — proveniência de token exchange em Observe | **Aceito com rollout, P0** | `TokenExchangeOptions.ProvenanceMode` agora inicia em `Enforce`; P0.2 mantém somente o inventário e a remoção de overrides `Observe` existentes nos ambientes. |
| S5 — vault plaintext por default | **Aceito, gate operacional P0** | O startup agora impede `PassThroughKeyVault` fora de Development e o template habilita criptografia. Resta executar e comprovar a migração `pt1` nos ambientes conforme o plano GLM/Vault. |
| S13 — replay DPoP distribuído | **Sem mudança funcional** | O get/set isolado não é a autoridade final: `RollingDpopReplayCache` inclui insert único no banco. Adicionar somente teste de composição para impedir remoção acidental dessa camada. |
| S13 — orçamento de nonce GCM | **Diferido, P2** | Risco teórico dependente de volume. Medir operações por versão e definir limite antes de criar rotação por contagem. |
| S13 — CSP | **Já canônico** | Calibração e enforcement permanecem em `PLAN-PRODUCTION-READINESS.md` e `RUNBOOK-CSP-CALIBRATION.md`. |
| S13 — `EnvelopeCrypto.Wrap/Unwrap` | **Aceito como limpeza, P2** | Corrigir comentários/modelo que atribuem o wrapping real a AES-GCM ou remover o caminho morto e seu teste. |

Referência normativa de S11: [RFC 9101, seções 4 e
5](https://www.rfc-editor.org/rfc/rfc9101.html#section-4).

## P0 — bloquear postura insegura e downgrades imediatos

### P0.2 Concluir os rollouts que hoje permanecem observacionais

**Alvos:** SCIM, token exchange, personal tokens, CIBA, credential mutations,
public origin e autorização Management.

- [ ] SCIM: inventariar clientes negados nos ambientes, provisionar a
  allow-list e remover overrides `Observe` depois de uma release sem decisões
  de compatibilidade
- [ ] Token exchange: caracterizar `azp`/`client_id` dos subject tokens,
  corrigir emissores ambíguos, remover overrides de provenance `Observe` e
  manter atenuação de scopes/resources como invariante
- [ ] Personal tokens e CIBA: concluir inventários e remover overrides
  `Observe` conforme `PLAN-SECURITY-HARDENING-WAVE-2.md`
- [ ] Credential mutations: provar a cerimônia real de step-up e remover
  overrides `Audit`, conforme `PLAN-GPT-5-REMAINING.md`
- [ ] Public origin: configurar issuer/public URL canônico em todos os hosts e
  remover overrides `Audit`; nenhum link de segurança pode depender de Host não
  confiável
- [ ] Management: auditar as configurações implantadas e remover
  `RequireAuthorization=false` fora de Development, salvo acknowledgement
  temporário que bloqueie certificação/go-live

**Concluído quando:** produção não contém um modo permissivo sem acknowledgement
válido e todas as exceções temporárias têm data de remoção observável.

### P0.5 Executar a migração criptográfica nos ambientes

**Plano canônico:** `PLAN-GLM-5-2-REMAINING.md` P0.1 e
`RUNBOOK-VAULT.md`. Os guards, defaults, fallbacks e testes locais já foram
entregues.

- [ ] Por ambiente, inventariar e regravar todos os valores `pt1.`, configurar
  `Enabled=true`, comprovar zero leituras legadas durante a janela definida e
  registrar backup restaurável, owner e rollback sem incluir segredos

**Concluído quando:** nenhum ambiente contém valor reversível legado e a prova
redigida de migração/rollback está anexada ao gate de release.

## P2 — manutenção e evolução arquitetural

### P2.1 Reduzir blast radius sem misturar a mudança com os gates P0

- [ ] Decompor `AuthorizationController` por grant conforme
  `PLAN-GLM-5-2-REMAINING.md` P1.7, preservando rotas e caracterização de tokens
- [ ] Dividir `SufficitIdentityOptions` por feature e manter uma façade de
  binding compatível por uma release
- [ ] Reavaliar a unificação dos enums de enforcement depois que contributors e
  acknowledgements estiverem estáveis; não criar uma migração de tipos sem
  benefício mensurável
- [ ] Remover ou corrigir `EnvelopeCrypto.Wrap/Unwrap` e os comentários de
  entidade que não descrevem o wrapping real por Data Protection

### P2.2 Evoluir formato de token e limites criptográficos com evidência

- [ ] Selecionar JWT/reference token por cliente/recurso conforme
  `PLAN-GPT-5-REMAINING.md` P1.13, com migração sem flag day
- [ ] Medir encryptions por key name/version e definir orçamento de mensagens
  antes de automatizar rotação por contagem de nonce GCM
- [ ] Manter teste de composição garantindo que `RollingDpopReplayCache`
  contenha a camada atômica de banco enquanto o cache distribuído usar get/set

### P2.3 Prova externa de produção

- [ ] Executar conformance OAuth/OIDC/FAPI/SSF aplicável às capabilities
  anunciadas
- [ ] Commissionar auditoria externa de DPoP, JAR/JARM, CIBA, mTLS, token
  exchange e vault após P0/P1
- [ ] Concluir CSP, Redis multi-replica, certificados e disaster recovery em
  `PLAN-PRODUCTION-READINESS.md`

## Sequência de rollout

1. **Release de observação:** contributors completos, telemetry, testes e
   acknowledgements estruturados; sem mudança de decisão para tráfego existente.
2. **Inventário e correção:** remover findings reais, migrar `pt1`, corrigir
   clientes/subject tokens e registrar somente exceções temporárias.
3. **Release fail-closed:** remover o guard de presença, ligar o default real,
   fechar PKCE/JAR/sender constraint/fallbacks e bloquear novas regressões.
4. **Expiração de compatibilidade:** retirar acknowledgements vencidos,
   `Observe` de SCIM após uma release limpa e adapters de configuração antigos.
5. **Custódia e certificação:** concluir provas externas antes do go-live
   irrestrito.

## Verificação mínima

- `dotnet build Sufficit.Identity.sln -c Release`
- `dotnet test src/tests/Sufficit.Identity.Tests.csproj -c Release`
- Testes focados de posture check e startup não-Development
- Testes de Management/Provisioning/DCR para PKCE
- Testes JAR de parâmetros externos, tipos estruturados, replay e `jwks_uri`
- Testes DPoP/mTLS de emissão, refresh e consumo
- Rehearsal de rolling deployment antes de remover cada compatibilidade

## Gate de encerramento

Este plano pode ser arquivado somente quando:

- todo modo permissivo de produção está enforcing ou possui exceção temporária
  ainda válida e auditável;
- Management, provisioning e DCR compartilham PKCE para todo auth-code client;
- JAR não usa parâmetros externos ao JWT validado;
- DPoP e mTLS não sofrem downgrade quando apresentados em conjunto;
- produção não usa `pt1`/PassThrough;
- os gates canônicos de produção, vault, autorização e auditoria externa foram
  concluídos.
