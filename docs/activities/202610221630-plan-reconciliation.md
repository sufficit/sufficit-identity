# Reconciliação do plano com o código e com a produção

**22/10/2026.** Os itens abertos de `PLAN-IDENTITY.md` foram conferidos um a
um contra o código atual, os testes, as atividades e a configuração dos três
nós de produção (não contra as caixas, que nunca são marcadas). O plano estava
desatualizado sobretudo do lado da produção: vários itens "operacionais" já
estavam feitos. Na partida, a checagem de postura de produção informa
"no unresolved permissive security settings are active".

## Retirados do plano (resolvidos)

| Item | Evidência |
|------|-----------|
| A4 — step-up de mutação de credencial em `Enforce` | Padrão `Enforce` (`CredentialMutationSecurityCoordinator.cs`), produção não sobrescreve. |
| B3 — procedência na troca de token em `Enforce` | Padrão `Enforce` (`TokenGrants.cs`), produção não sobrescreve. |
| B5 — CIBA por cliente em `Enforce` | Padrão `Enforce` (`CibaOptions.cs`); CIBA desligado em produção. |
| B8 — validação de recurso por cliente | Não existe modo Observe: `oi_rprm` sempre aplicado (`OpenIddictServerConfiguration.cs`, `ResourceIndicatorTests`). |
| C1 — cofre ligado, zero `pt1.` | `Sufficit:Vault:RequireEncryptionInProduction=true`, KEK por certificado; 0 de 80 segredos em `pt1.`. Fica no plano a prova de backup/rollback e a declaração `SecretMigrationComplete`. |
| C4 — RabbitMQ com TLS verificado | `Sufficit:Exchange:RabbitMQ:UseTls=true`, `RequireTls=true`, `TlsServerName=exchange.example.com`. Ficam SMTP e o TLS do banco. |
| D1 — inventário de origens e CSP em bloqueio | `Csp:ReportOnly=false`, `UseNonce=true`, política explícita. Ficam os 9 atributos `style="…"` e a validade do `AcknowledgeReportOnly`. |
| D2 — origem pública em `Enforce` | Padrão `Enforce` (`PublicOriginResolver.cs`), produção não sobrescreve. |
| D3 — topologia explícita | `DeploymentTopology=ClusteredBehindTrustedProxy`, `RateLimit:FailOnUntrustedProxy=true`, `DistributedCache:RequireShared=true`. Fica o smoke test de duas réplicas. |
| D4 — inventário de modos em produção | Postura de produção sem configuração permissiva pendente. Fica para os demais ambientes. |
| D5 — Redis real | Cache distribuído compartilhado com `RequireShared=true` nos três nós. Fica o ensaio de várias réplicas. |
| F13 — separar `DbContext` | Já estava **retirado por decisão** (custo em SQL sequenciado à mão no Galera); saiu do plano. |
| G4 — grants legados migrados | `LegacyGrants:Password=false`, `LegacyGrants:None=false`; posture sem `legacy-grants-enabled`. |
| G4 — PKCE S256 | Obrigatório e `plain` removido (`OpenIddictServerConfiguration.cs`); produção sem exceção. |
| G4 — distribuição de chaves (PFX em toda réplica) | Três nós emitindo e validando tokens uns dos outros desde o corte de agosto; `deploy.py` preserva `certificate*.pfx`. |
| G4 — paridade do Management | O sistema legado foi aposentado; não há administração legada a aprovar. |
| G4 — nenhum segredo no repositório | gitleaks em todo o histórico, falhando a CI (`ci.yml`). |

## Corrigido no plano

- **A4**: o plano dizia que os leitores de evidência de MFA estavam
  unificados. Não estão: o SCIM tem leitor próprio
  (`ScimServiceCollectionExtensions.cs`) ao lado de `MfaEvidencePolicy`.
- **C1, C4, D1, D4, D5**: itens reescritos com o que de fato falta.

## Avisos de postura que restam em produção

1. Mesmo certificado para assinatura e criptografia (C2, bloqueado).
2. Claims sem mapeamento de escopo nos access tokens (B2).
3. Delegação aceita login de até 168 h (recomendado ≤ 24 h).
4. SCIM ligado com allow-list vazia (recusa tudo).

## Achados para trabalho futuro (já no plano)

- E2: a console mostra `SecretHint` (derivado do hash do segredo), que o plano
  proíbe.
- E8: textos fixos em `passkeys.js` e em `UserManagementService.TwoFactor.cs`.
- F8: os scripts aditivos 085–105 nunca são comparados com a instalação nova.
- B9: `fapi2.expected-failures.json` aponta para `PLAN-FAPI2-CONFORMANCE.md`,
  que não existe.
