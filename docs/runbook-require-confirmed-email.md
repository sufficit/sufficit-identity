# Runbook — Ativar `RequireConfirmedEmail` em produção

**Item:** 2.3 [M3] do `docs/eval/PLAN-2026-07-25-claude-fable-5.md`
**Option:** `Sufficit:Identity:SignIn:RequireConfirmedEmail` (default `true`)

## Contexto

`RequireConfirmedEmail=true` (secure-by-default) faz com que o
`SignInManager.CanSignInAsync` — consultado por **todos** os grants do
`AuthorizationController` (password, authorization_code, refresh, device,
token exchange) — rejeite usuários com `EmailConfirmed=false`. Combinado com a
superfície pública de auto-registro (`Sufficit:Identity:Register:Enabled`, lida
no módulo de UI incorporado), isto fecha o buraco "registrar com e-mail alheio e usar a
conta".

O STS colapsa o caso "não confirmado" no MESMO `invalid_grant` genérico de
"senha errada" (`AuthorizationController.ExchangeForPasswordAsync`), então NÃO
introduz enumeração de usuários.

## Por que este runbook existe

Virar essa flag em produção **sem preparação** trava dois grupos de usuários:

1. **Usuários legados** no banco com `emailconfirmed=0`.
2. **Usuários de login externo** (Google/GitHub/Facebook) cujo provedor não
   asseverou `email_verified` no momento do cadastro.

## Passos de rollout (faça na ordem)

### 1. Levantar usuários legados não confirmados

```sql
SELECT COUNT(*) AS unconfirmed_count
FROM users
WHERE emailconfirmed = 0;

-- Detalhe por domínio (ajuda a decidir migração vs. reconfirmação):
SELECT
    SUBSTRING_INDEX(email, '@', -1) AS domain,
    COUNT(*) AS cnt
FROM users
WHERE emailconfirmed = 0
GROUP BY domain
ORDER BY cnt DESC;
```

### 2. Decidir a migração dos legados

- **Confirmar em massa** os que já logavam (prova indireta de posse histórica):
  ```sql
  UPDATE users
  SET emailconfirmed = 1
  WHERE emailconfirmed = 0
    AND lastlogin_at IS NOT NULL
    AND lastlogin_at > (NOW() - INTERVAL 90 DAY);
  ```
- **Forçar reconfirmação** dos restantes: deixar `emailconfirmed=0` e garantir
  que a UI tem fluxo de reenvio de confirmação acessível no login.
- Documentar a decisão (quantos confirmados em massa, quantos em reconfirmação)
  e a data, neste runbook ou em `docs/activities/`.

### 3. Garantir ClaimActions de TODOS os provedores externos

O STS só registra o `ClaimAction` `email_verified` para **Google**
(`src/sts/ServiceCollectionExtensions.cs`, `AddExternalProviders`).
**Facebook e GitHub não o emitem hoje.** Antes de ativar a flag:

- Em `src/ui/Sufficit.Identity.UI`, confirmar que `ExternalLoginController` lê
  `email_verified` do `Principal` e seta
  `EmailConfirmed = emailVerified` apenas quando o provedor assevera `true`
  (já faz — verificar a versão compilada na solução única).
- Para provedores que **não** asseveram `email_verified` (Facebook clássico,
  GitHub sem escopo extra de e-mail verificado), decidir uma das políticas:
  - não auto-confirmar → usuário externo recebe e-mail de confirmação pós-cadastro;
  - ou desabilitar esse provedor até resolver.

### 4. Garantir fluxo de reenvio de confirmação

A UI (`src/ui/Sufficit.Identity.UI`) deve expor um "reenviar e-mail de confirmação"
acessível a partir da tela de login para usuários cuja conta existe mas não
está confirmada. Sem isso, um usuário legado não confirmado fica sem caminho
de saída.

### 5. Ativar a flag por ambiente

`appsettings.<env>.json` (ou env var / User Secrets):

```json
"Sufficit": {
  "Identity": {
    "SignIn": {
      "RequireConfirmedEmail": true
    }
  }
}
```

Já é o default — este passo é só registrar que a decisão foi tomada
conscientemente para o ambiente, e que os passos 1-4 foram cumpridos.

### 6. Monitorar pós-ativação

- Acompanhar métricas/log de `invalid_grant` no password grant — um pico
  sustentado pode indicar usuários legados travados que a migração (passo 2)
  não cobriu.
- Acompanhar cadastros via login externo que ficam presos em
  `emailconfirmed=0` (problema do passo 3).

## Rollback

Voltar `RequireConfirmedEmail=false` no `appsettings.<env>.json`. Não destrói
dados; usuários voltam a poder logar sem e-mail confirmado (estado
pré-ativação). Útil como válvula de escape se os passos 1-4 foram
subestimados.
