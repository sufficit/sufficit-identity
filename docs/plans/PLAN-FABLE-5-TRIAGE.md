# Triage — EVALUATION-2026-08-15-claude-fable-5 vs HEAD 719ce33

> **Status:** ACTIVE. Reconciled on 2026-08-16 by GLM-5.3 against `719ce33`.
> Avaliador alvo: `e6a76d5` (F-8 batch) — **não viu** A2/A3/A4/A6/A10,
> remoção do multi-tenant, tooling de deploy e migração SUI-pacote.
> Fonte: [`EVALUATION-2026-08-15-CLAUDE-FABLE-5.md`](../evaluations/EVALUATION-2026-08-15-CLAUDE-FABLE-5.md)

## 1. H-1 (ALTO) — parcialmente FALSO para produção

O avaliador leu `deploy/local/appsettings.json` (referência local, gitignored).
Verificado por SSH nos 3 servers de produção:

| Config | deploy/local (o que ele leu) | Produção real | Clientes afetados |
|---|---|---|---|
| `LegacyGrants:Password` (ROPC) | `true` | **`false`** ✓ | 0 com a permissão |
| `LegacyGrants:None` | `true` | **`true`** ⚠️ | 0 com `ResponseTypes.Token` (config morta) |

**ROPC DESLIGADO em produção.** `None: true` é dead config mas deve ser limpa.
O `deploy/local/appsettings.json` está desatualizado e induz em erro.

### Ação imediata

- [x] `LegacyGrants:None: false` nos 3 servers + `deploy/local/appsettings.json` corrigido
  *(executado 2026-08-16; verificado: `"None": false` + `"Password": false` nos 3 servers)*
- [ ] **A-1 (ver abaixo)** teria barrado no boot

## 2. Config de produção confirmada problemática (verificada por SSH)

| Achado | Estado nos 3 | Ação | Status |
|---|---|---|---|
| **M-4** mesmo `certificate.pfx` signing+encryption | ⚠️ Confirmado | Gerar cert dedicado → trocar em janela | ⏳ **Bloqueado** — [runtime .NET rejeita PFX novo](../activities/202608161930-pfx-encryption-cert-investigation.md); cert 10y RSA-3072 já nos servers |
| **M-5** CSP `connect-src wss: ws:` | ~~Confirmado~~ | Remover (o SignalR same-origin = `'self'`) | ✅ **Corrigido** 2026-08-16 — `connect-src 'self'` nos 3 servers |
| **M-3** KEK `dataprotection` compartilha ring com cookies/antiforgery | ~~Confirmado~~ | Migrar p/ `certificate` (KEK dedicado) | ✅ **Corrigido** 2026-08-16 — `KeySource=certificate` + KEK dedicado nos 3 servers |

## 3. Já corrigidos pelo trabalho GLM-5.3 (avaliador não viu)

| Achado do avaliador | Commit | O que foi feito |
|---|---|---|
| **A-2** god-controller de grants | `c10aee3` | AuthorizationController 1569→687 linhas; `ITokenGrantHandler` ×5 + `TokenGrantDispatcher` com DPoP preamble único |
| **A-7** build cross-repo irmão SUI | `ae458b2` + `03f5f3b` | SUI como **pacote NuGet** nuget.org; referência condicional (irmão local OU pacote) |
| **L-4** só RS256 | `d90a77c` | PS256/ES256/EdDSA via `SigningAlgorithms`; alg por versão de chave no JWK |
| **M-9** pt1 sem controle | `7dc956a` | Janela `PlaintextReadCompatibility` bounded (owner/reason/expiry ≤180d), deadline por leitura |
| **A-3** parcialmente | `c10aee3` | Controller quebrado; `SufficitIdentityOptions`/`ServiceCollectionExtensions` ainda grandes |
| (sem ID) tooling de deploy | `1123b55` + `4440844` | deploy.py endpoints-style + migrator estático multimaster |
| (sem ID) CI 30 runs vermelhos | `113177a`…`82455b3` | Sibling checkout → pacote; locks; xUnit analyzers |
| (sem ID) multi-tenant decorativo | `cd67f51` | Sistema removido por decisão de produto (isolamento externo) |
| (sem ID) emissão privilegiada ×4 | `13e846a` | `IPrivilegedTokenMintingService` unifica personal/provisioning/operator tokens |
| (sem ID) CIMD ausente | `ae22303` | Client ID Metadata Documents implementado (draft-ietf-…-02) |

## 4. Ainda válidos — código (priorizados por impacto)

### P0 — fechar nesta janela

- [ ] **A-1 — Cobertura do `IProductionPostureContributor`** (o avaliador tem razão: o padrão existe, a cobertura ficou atrás da superfície de config). Adicionar findings com o contrato de `Acknowledgement` existente para:
  - [ ] `LegacyGrants:Password/None=true` (H-1 — teria barrado a regressão)
  - [ ] Token-exchange habilitado com allow-list vazia (M-2)
  - [ ] Conteúdo da policy CSP com wildcards em `connect-src`/`script-src` (M-5)
  - [ ] Thumbprints signing==encryption em produção (M-4)
  - [ ] `KeySource=dataprotection` em produção (M-3)
  - [ ] Passkey sem `userVerification=Required` configurado (M-1)
  - [ ] `IncludeUnmappedClaimsInAccessTokens=true` (M-6)

- [ ] **M-1 — Passkey afirma `amr=mfa`/`acr=loa3` sem medir User Verification** (`AspNetCoreIdentityPasskeyService.cs:392`). O `Set()` roda ANTES da cerimônia, incondicional. Introduzir `IPasskeyAssurancePolicy` que (a) gera request options com `userVerification=Required`; (b) deriva `amr`/`acr` do resultado UV real da cerimônia; (c) move o `Set()` para depois do sucesso.

### P1 — curto prazo

- [ ] **M-2 — Token exchange default-on, proveniência condicional.** Ou default `Enabled=false`, ou proveniência incondicional (exigir `azp` no subject_token sempre). + Posture finding.
- [ ] **M-8 — Remembered-MFA `amr=mfa` por até 90d.** No step-up do Management, não honrar remembered-MFA (o caminho `force_mfa` já faz isso — aplicar a toda projeção de dispositivo lembrado onde step-up é exigido). Encurtar default. Vincular cookie ao security stamp.
- [x] **M-5 (config) — CSP `wss: ws:` removido** nos 3 servers. SignalR same-origin é `'self'`. ✅ 2026-08-16
- [x] **H-1 (config) — `None: false`** nos 3 servers + deploy/local corrigido. ✅ 2026-08-16
- [ ] **L-1 — Enumeração interativa:** `locked_out`/`not_allowed` distinguíveis. Colapsar em erro genérico.
- [ ] **L-5 — Validador anuncia `implicit`/`password`:** remover `implicit`; gatear `password` em `LegacyGrants.Password`.
- [ ] **L-6 — Default interface method bug:** `IIdentityUserSessionRevoker.RevokeAsync` default descarta `exceptBrowserSessionId`. Tornar abstrato ou lançar.

### P2 — médio prazo

- [ ] **M-4 (config) — Separar cert signing/encryption.** Gerar cert dedicado, trocar `EncryptionPath` em janela com rotação de tokens. Setar `RequirePurposeSeparation=true`.
  *⏳ Bloqueado: o runtime .NET 10.0.10 do server rejeita qualquer PFX que não o original (nem OpenSSL, nem .NET SDK). Ver [investigação completa](../activities/202608161930-pfx-encryption-cert-investigation.md). O cert `certificate-encryption.pfx` (RSA-3072, 10 anos, CN=sufficit-identity-token-encryption) já está deployado nos 3 servers. Solução recomendada: gerar o cert NO server via comando CLI do próprio Server.dll (`--generate-encryption-cert`).*
- [x] **M-3 (config) — KEK `certificate` dedicado** em vez de `dataprotection`. ✅ 2026-08-16 — `KeySource=certificate` com `/etc/sufficit/identity/vault-kek.pfx` (10 anos). O vault-kek.pfx (gerado anteriormente) carregou sem problemas no runtime — não atingido pela incompatibilidade PFX do cert de token.
- [ ] **M-7 — Lockout 5/5min →** backoff exponencial ou janela ≥15min; `HumanVerificationFlow.Login` com CAPTCHA após N falhas por conta/IP; partição por-conta no rate limiter.
- [ ] **M-6 — Claims unmapped →** inventariar resource servers, depois `IncludeUnmappedClaimsInAccessTokens=false` (allow-list estrita).
- [ ] **L-2 — Swagger** gatear atrás de `!IsDevelopment()` ou policy.
- [ ] **L-3 — GCM budget** auto-rotacionar DEK no budget ou dirigir rotação do contador OTel durável.

### P3 — dívida de arquitetura (do avaliador, parcialmente válida)

- [ ] **A-3 restante:** `SufficitIdentityOptions` (1812 linhas) e `ServiceCollectionExtensions` ainda god-files. Extrair registrador por feature (`AddDpop`, `AddFapi2`, …) cada um dono das suas options + wiring + posture contributor + discovery metadata.
- [ ] **A-5:** `amr` MFA setado em 6 lugares → `IMfaEvidencePolicy` única em Application.Abstractions; `DemandAsync`/`TryWriteAuditAsync` ×6 serviços → `ManagementOperationExecutor`; `ManagementOptions` duplicado (STS × Abstractions).
- [ ] **A-6:** `#if APPLICATION_CONTRACTS` dual-compilação → mover interfaces+DTOs para arquivos reais em Abstractions, Management referencia normalmente.

## 5. Observações sobre a avaliação em si

**Pontos fortes do avaliador:** leu código real, verificou adversarialmente, distinguiu código×config-deploy, propostas de design concretas com file:line, honesto sobre o que já estava forte (§3.4).

**Erros/limitações:**
- **H-1** parcialmente falso: leu `deploy/local/appsettings.json` como se fosse a config de produção. O arquivo local está desatualizado (`Password: true` lá, `false` nos servers). O `None: true` está correto em ambos, mas é config morta.
- **Não viu A2/A3/A4/A6/A10** (HEAD dele = `e6a76d5`): ainda trata `AuthorizationController` como god-object de 1569 linhas, acoplamento cross-repo SUI como problema aberto, RS256-only como limitação. Tudo já resolvido.
- **M-9** subestima o fix existente: a janela bounded já foi adicionada (`7dc956a`) — o avaliador viu o fix mas pede HMAC-keyed marker mesmo assim. Válido como endurecimento adicional; severidade menor.
- **Arquitetura 7.0** penaliza god-objects que em parte já foram quebrados. Nota real em `719ce33` seria ~7.5.
- **Prontidão 6.0** penaliza "build cross-repo" (resolvido) e "regressão ROPC" (parcialmente falso). Nota real ~6.5-7.0.

**Concordo integralmente com A-1 como prioridade máxima arquitetural** — o `ProductionPostureCheck` é o melhor padrão de segurança do repo, mas a cobertura ficou atrás da superfície de config. Estender a cobertura é a forma mais barata de transformar toda regressão de config em uma decisão deliberada, atribuída e expirável.

## 6. Sequência de execução recomendada

| Ordem | O quê | Tipo | Risco |
|---|---|---|---|
| 1 | `None: false` + CSP limpo nos 3 servers + deploy/local corrigido | Config | Zero |
| 2 | A-1: cobertura do posture check (7 findings novos) | Código | Baixo |
| 3 | M-1: `IPasskeyAssurancePolicy` (UV medido, `Set()` pós-cerimônia) | Código | Médio |
| 4 | M-2: token exchange proveniência incondicional | Código | Baixo |
| 5 | M-8: remembered-MFA não honra step-up | Código | Baixo |
| 6 | L-1/L-5/L-6: enumeração + validador + DIM bug | Código | Baixo |
| 7 | M-4/M-3: cert dedicado encriptação + KEK cert | Config + janela | Médio |
| 8 | M-7/M-6/L-2/L-3: lockout/CAPTCHA/claims/swagger/GCM | Config+Code | Baixo |
| 9 | A-3/A-5/A-6: dívida arquitetural restante | Refactor | Médio |
