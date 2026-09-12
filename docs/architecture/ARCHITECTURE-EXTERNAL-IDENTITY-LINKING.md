# Vínculo de identidade externa

## Problema

Um provedor externo afirma um endereço de e-mail. Afirmar não é provar. Vários
provedores amplamente usados nunca emitem `email_verified`, e um que emite pode
estar afirmando algo que não checou.

Se uma afirmação não provada bastar para **criar a conta local e vincular** a
identidade externa, existe um ataque de sequestro antecipado:

1. O atacante registra o endereço da vítima num provedor que não verifica
   endereços e entra no Identity.
2. Nasce a conta local, `EmailConfirmed=false`, com o login do atacante
   vinculado. O atacante não consegue entrar ainda, porque a política de
   sign-in exige e-mail confirmado.
3. A vítima tenta se registrar e recebe erro genérico; tenta recuperar senha e
   nada acontece, porque a conta não está confirmada.
4. A vítima usa "reenviar confirmação", confirma o endereço — e o vínculo do
   atacante sobrevive à confirmação. A partir daí o atacante entra pelo
   provedor externo, com sessão plena.

O passo que quebra tudo é o 2: **o vínculo precede a prova**.

## Decisão

Nada é persistido enquanto o controle do endereço não for estabelecido.

A decisão de "está estabelecido?" é uma fronteira explícita,
`IExternalIdentityLinkingPolicy`
(`src/application/Sufficit.Identity.Application.Abstractions/Accounts/ExternalIdentityLinking.cs`),
com três respostas:

| Decisão | Significado |
|---|---|
| `Immediate` | Controle estabelecido; cria e vincula na mesma requisição. |
| `RequiresEmailVerification` | Não estabelecido; nada é persistido e uma mensagem de prova é enviada. |
| `Denied` | O provedor pode autenticar vínculos existentes, mas nunca criar conta. |

A política é uma fronteira, e não uma condição embutida, porque a resposta é
decisão de implantação e não fato de protocolo. Uma implantação cujo único
provedor é um IdP corporativo próprio pode confiar nos endereços dele; uma que
federa provedores de consumo não pode. O mesmo binário serve as duas sem que
nenhuma edite um `if`.

## Implementação padrão

`ConfigurableExternalIdentityLinkingPolicy` (`src/sts/ExternalIdentityLinkingPolicy.cs`)
avalia, nesta ordem: deny-list, chave `RequireVerifiedEmail`, afirmação do
provedor, allow-list de provedores confiáveis.

**Nenhum provedor é nomeado em código.** Quais esquemas existem, e em quais
deles a implantação acredita, é configuração
(`Sufficit:Identity:ExternalIdentities`, ver `src/sts/Options/ExternalIdentityOptions.cs`).

## Fluxo com prova

```
callback do provedor
  └─ política: RequiresEmailVerification
       ├─ PendingExternalIdentityStore.CreateAsync  → ticket de uso único
       ├─ ExternalIdentityVerificationMessenger     → mensagem ao endereço
       └─ resposta: EmailVerificationRequired  (nenhuma linha gravada)

GET /account/externallink/confirm?ticket=…
  └─ IExternalSignInService.CompletePendingLinkAsync
       ├─ redime o ticket (consome antes de usar)
       ├─ recusa se o endereço já foi reivindicado nesse meio-tempo
       └─ cria a conta JÁ confirmada + vincula + autentica
```

Resgatar o ticket **é** a prova: ele só foi entregue ao endereço em disputa,
então quem o apresenta controla a caixa. Por isso a conta nasce confirmada —
exigir uma segunda confirmação provaria o mesmo endereço duas vezes.

### Propriedades do ticket

| Propriedade | Como |
|---|---|
| Uso único | Removido antes de ser usado (`RedeemAsync`), então um replay não encontra nada |
| Tamanho de credencial | 256 bits de `RandomNumberGenerator` |
| Não legível no banco | A chave armazenada é o SHA-256 do ticket |
| Janela curta | `VerificationLifetimeMinutes`, padrão 30, limitado a 5..1440 |
| Compartilhado entre réplicas | Vive em `IProtocolStateStore` (tabela `protocolstateentries`), não em cookie |

Não carrega URL de retorno. A prova é resgatada da caixa de e-mail, comumente em
outro navegador, onde a requisição de autorização original já não existe — e um
destino de redirecionamento que sobrevive a uma mensagem é mais uma coisa para
validar.

## Dados legados

O fluxo atual nunca vincula antes da prova, mas contas criadas pelo
comportamento anterior ainda carregam o vínculo. `ConfirmEmailAsync`
(`src/sts/AspNetCoreIdentityAccountOnboardingService.cs`) remove os logins
externos de uma conta que estava não confirmada no momento em que o dono
legítimo prova o endereço.

Isso é condicionado a `SignIn:RequireConfirmedEmail`. Só sob essa política é
**impossível** existir vínculo legítimo numa conta não confirmada: vincular um
provedor exige sessão autenticada, e autenticar exige o endereço confirmado. Sem
a política, um usuário pode legitimamente entrar sem confirmar e vincular um
provedor — e apagar seria destruir trabalho dele.

## Verificação de postura

`StsProductionPostureContributor` reporta dois achados:

| Achado | Quando |
|---|---|
| `external-identity-unverified-email` | `RequireVerifiedEmail=false` |
| `external-identity-trusted-providers` | Há provedores na allow-list, que são listados no texto |

O segundo não é um erro: é um lembrete auditável de que alguém decidiu acreditar
naqueles provedores.

## Testes

`src/tests/ExternalIdentityLinkingTests.cs` — decisões da política, uso único do
ticket, fiação no host composto (o padrão do servidor real exige prova) e os dois
lados do expurgo legado: conta não provada perde os vínculos, conta já provada os
mantém.

O teste do expurgo foi verificado por mutação: desligado o expurgo, ele falha.
