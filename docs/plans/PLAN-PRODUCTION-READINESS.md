# Production readiness — remaining work

> **Status:** ACTIVE. Findings from the earlier production-readiness baseline
> were remediated, but later independent evaluations identified residual
> protocol and trust-boundary work. Those implementation items are tracked in
> `PLAN-GPT-5-REMAINING.md` and `PLAN-GLM-5-2-REMAINING.md`; this plan owns the
> remaining certification, deployment assurance and product-quality gates.
> O procedimento e o formato de evidência por ambiente estão em
> `RUNBOOK-PRODUCTION-EVIDENCE.md`.

## Certification
- [ ] Executar conformance OAuth/OIDC/FAPI/SSF para as capabilities anunciadas e submeter os perfis aplicáveis à certificação formal
- [ ] Commissionar auditoria externa de DPoP, CIBA, JARM, JAR, mTLS, token exchange, SSF e vault; corrigir e retestar findings impeditivos

## Deployment assurance
- [ ] Inventariar e rotacionar credenciais/certificados legados de banco e provedores, migrar `deploy/local/` para o secret store aprovado e anexar manifesto redigido com owner, versão, estado e data de retirada
- [ ] Por ambiente, inventariar SCIM, token exchange, personal tokens, CIBA, credential mutations, origem pública e Management; remover `Observe`/`Audit`/authorization-off ou registrar exceção temporária válida
- [ ] Habilitar o vault e provar zero valores/leituras `pt1.`, backup restaurável e rollback sem registrar material sensível
- [ ] Executar `RUNBOOK-CONFIRMED-EMAIL` (rollout e migração dos usuários legados)
- [ ] Calibrar CSP na UI Blazor real e configurar `ReportOnly=false`
- [ ] Configurar Redis `IDistributedCache` real e passar o ensaio de emissão/consumo/replay entre múltiplas réplicas
- [ ] Inventariar e rotacionar certificados, provar separação signing/KEK e executar restore/disaster recovery

**Procedimento canônico:**
[`RUNBOOK-PRODUCTION-EVIDENCE.md`](../runbooks/RUNBOOK-PRODUCTION-EVIDENCE.md).
Os itens acima vieram do plano Claude Fable 5 e permanecem abertos aqui até
existir evidência real de cada ambiente; a transferência não declara o rollout
concluído.

## Product quality
- [ ] WCAG 2.2 AA accessibility audit for both embedded UIs
- [ ] Localization (extract runtime copy, currently pt-BR hardcoded)
- [ ] SCIM: bulk, sorting, ETags (intentionally unadvertised — enable per demand)

## Forward-looking protocol work
- [ ] FAPI 2.0 Advancing Profile (requires encrypted request objects beyond JAR)
- [ ] Rich Authorization Requests (RAR — `authorization_details`)
- [ ] OpenID Federation (entity statements, trust chains)
- [ ] SSF durable outbox/retry state (persistent delivery guarantees beyond best-effort)
