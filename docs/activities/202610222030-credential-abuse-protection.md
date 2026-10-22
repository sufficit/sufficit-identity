# Proteção contra tentativa de senha, compartilhada entre os nós (D6)

**22/10/2026.**

## Antes

O limitador era um `PartitionedRateLimiter` em memória, por processo,
particionado por caminho, método e IP: cada um dos três nós contava sozinho e
não havia dimensão de conta. Um ataque que testa poucas senhas em muitas
contas, ou a mesma conta a partir de muitos IPs, não esbarrava em nada além do
bloqueio do ASP.NET Identity (5 erros em 5 minutos, compartilhado porque fica
no banco). E um usuário inexistente respondia mais rápido que uma senha
errada, porque nenhum hash era calculado.

## Agora

`CredentialAbuseGuard` (STS), no login por senha (`/account/login/password`):

- **Contadores compartilhados** no Redis da implantação (`INCR` com expiração,
  janela de 15 min): por conta (HMAC do nome normalizado; o nome nunca vai ao
  Redis) e por IP. Sem Redis, contador por processo.
- **Decisão antes de olhar a senha**, por ordem:
  1. IP com ≥ 200 falhas → recusado (`too_many_attempts`);
  2. conta com ≥ 5 falhas ou IP com ≥ 20 (espalhamento por contas) → exige
     verificação humana (reCAPTCHA, fluxo `Login`); sem o token válido a senha
     nem é conferida (`verification_required`, a página mostra o widget por
     `verify=1` enquanto durar);
  3. conta com ≥ 3 falhas → espera 1, 2, 4… até 8 s.
- Senha certa zera a conta (o IP não: um acerto não desculpa um
  espalhamento). Falha do Redis nunca bloqueia: segue sem proteção e registra.
- **Modos** `Off`/`Observe`/`Enforce` (`Sufficit:Identity:AbuseProtection:Mode`);
  padrão `Observe`: conta e registra "Credential abuse (observe): …" sem
  mudar nenhuma resposta. Limites configuráveis na mesma seção.
- **Tempo igual** para usuário inexistente: um hash descartável com o hasher
  configurado.
- Postura: avisos `credential-abuse-not-enforced` e
  `credential-abuse-account-key-derived` (chave do HMAC derivada do issuer
  quando `SUFFICIT_SECRET_IDENTITY_ABUSE_PROTECTION_ACCOUNT_KEY` falta).

## Para ligar

Observar os registros "Credential abuse (observe)" por alguns dias (atenção a
redes com NAT compartilhado, que somam falhas de muitos usuários num IP),
ajustar os limites e então `Mode=Enforce`.
