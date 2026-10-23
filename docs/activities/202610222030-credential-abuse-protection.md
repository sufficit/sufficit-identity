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

## Proxies confiáveis corrigidos (22/10/2026)

Avaliado se um "IP compartilhado" no contador poderia ser configuração de proxy:

- **Hoje correto:** o DNS aponta só para o proxy-1; o HAProxy sobrescreve
  `X-Forwarded-For` com a origem; o identity resolveu o IP real pelo HAProxy e
  ignorou um `X-Forwarded-For` forjado no acesso direto à :26501.
- **Faltavam dois proxies:** proxy-2 e proxy-3 também têm backend
  do identity e, ao cair o servidor local deles, encaminham pela internet a
  partir de 203.0.113.2 e 203.0.113.3, que nenhum nó conhecia (hoje só
  passam health checks, ~29 mil `HEAD /health` cada). Num failover, todos os
  usuários vindos deles virariam um IP só: limitador de 30/min e contador de
  abuso barrariam todo mundo.
- **Largo demais:** `172.16.0.0/16` confiava na rede local inteira (qualquer
  CT/VM/pod forjaria o IP); `15.177.0.0/16` (health checks AWS) e
  `198.51.100.4` (IP antigo de um datacenter) não são proxies.
- **IPv6 por /128:** um assinante gira endereços no próprio /64 e nunca chega
  a limite nenhum.

Feito: lista no banco de configurações (`trustedproxyconfiguration`, revisão
`7fe87722…`, evento de auditoria `trusted_proxies_updated`) só com os três
HAProxies — locais 172.16.1.0, 172.16.2.0, 172.16.3.0; públicos
203.0.113.1, 203.0.113.2, 203.0.113.3; IPv6 2001:db8:1::2000,
2001:db8:2::1000, 2001:db8:3::3000 — e `appsettings` reduzido a
`127.0.0.1/32` nos três nós (backup `.bak-trustedproxies-20261022`); 10 redes
efetivas. Limitador e contadores agrupam IPv6 por /64 (`2969577`). Conferido
depois: IP real pelo HAProxy e direto (IPv4), e `2001:db8:ff00::/64`
direto por IPv6.

## Segundo fator, e-mails e tempo de resposta (22/10/2026)

- **Propósitos com contadores próprios** (`CredentialAbusePurpose`): senha
  (conta + IP, chaves de antes), segundo fator e e-mail de conta. Errar
  códigos não mexe na contagem de senha, e vice-versa.
- **Código do autenticador e de recuperação:** por conta (o usuário que a senha
  já identificou; num circuito Blazor não há IP confiável). Atraso progressivo
  a partir de 3 erros; a partir de 5, recusado como bloqueado até a janela
  passar. Antes, só o bloqueio do Identity (5 em 5 min, renovável).
- **E-mails de recuperação e de confirmação:** no máximo 3 por conta em 15 min
  (`AccountEmailsPerWindow`); acima disso não envia — e a resposta é a mesma.
- **Tempo mínimo de 1,5 s** nas duas solicitações públicas por e-mail: conta
  inexistente respondia na hora, existente esperava token + SMTP.
- **Cadastro:** continua dizendo que o e-mail já tem conta (manda para o login
  com o e-mail preenchido). Decisão de UX, atrás do reCAPTCHA; mantida.

## Enforce ligado (23/10/2026)

Cerca de 18 h em `Observe` sem nenhuma decisão vinda de tráfego real (só os
testes do operador): nenhum falso positivo, nenhum ataque. `AbuseProtection:
Mode=Enforce` nos três nós (backup `.bak-abuse-enforce-20261023`); o aviso
`credential-abuse-not-enforced` saiu. Teste em produção com conta inexistente:
tentativas 1–3 normais, 4ª esperou 1 s, 5ª 2 s, 6ª recusada sem conferir a
senha (`verification_required`, `verify=1`), e a página renderiza o widget.
Desfazer: `Mode=Observe` e reiniciar.
