# Runbook — Ativar `RequireConfirmedEmail` em produção

**Roadmap:** item 2 de `docs/plans/PLAN-ROADMAP.md`
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
  e a data no registro operacional do ambiente.

### 3. Garantir ClaimActions de TODOS os provedores externos

Os adaptadores vivem em `src/sts/ServiceCollectionExtensions.ExternalProviders.cs`.
O Google só fornece prova aceita quando `email_verified=true` e o endereço é
Gmail ou há domínio hospedado `hd` (Google Workspace). Para endereço de terceiros,
`email_verified` isolado pode representar controle histórico, conforme a
[documentação do Google](https://developers.google.com/identity/sign-in/web/backend-auth).
A marca de perfil `verified` do Facebook não é usada como prova de e-mail.
O mapeamento do GitHub só aproveita `email_verified` quando efetivamente fornecido.

`IExternalIdentityLinkingPolicy` avalia a prova e as listas explícitas de provedores
confiáveis/negados. Sem prova, um cadastro novo aguarda a verificação por e-mail
antes de persistir conta ou vínculo. `TrustedEmailProviders` deve conter somente
provedores cuja validação de e-mail o operador conhece.

Para uma conta **já confirmada**, a prova confiável do mesmo e-mail permite
vincular o provedor e continuar o login automaticamente, sem pedir a senha local.
MFA, bloqueio e demais restrições continuam valendo. Contas locais não confirmadas
não são ativadas por esse caminho. Uma identidade externa já vinculada sempre
identifica sua conta original, mesmo que o e-mail do provedor mude.
`RequireVerifiedEmail=false` não dispensa prova ao vincular uma conta existente.

Na tentativa de cadastro por senha de e-mail já existente, a UI continua pelo
POST normal de login, sem criar conta ou trocar senha. Falhas retornam ao login
com o e-mail preenchido e a senha vazia; contas sem senha local mantêm disponíveis
as opções de acesso externo e recuperação.

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
