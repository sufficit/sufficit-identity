# Plano — usuários de sistema

Aberto em 21/10/2026. Estado: **implementado no identity** (21/10/2026; ver
"Registro de execução"). Consumidores pendentes.

## Problema

Hoje uma "conta de sistema" (`/management/service-accounts`) é um **cliente
OAuth sem usuário**: autentica por `client_credentials` e recebe papéis
declarados no próprio cliente. O token não tem um usuário como `sub`. Toda
aplicação que trata o chamador como pessoa falha com ele:

- `/connect/userinfo` não tem usuário a descrever. Respondia 500 até
  `46dec5e`; agora responde `401 invalid_token`.
- Resource servers que validam pelo userinfo (Run, sufficit-ai) rejeitam a
  chamada.
- Permissões, memória privada, avatar e auditoria por usuário não se aplicam.

Também não existe uma forma de obter um usuário válido que nunca faça login:

- A **credencial delegada** (`DelegatedCredentialIssuer`) exige um token de
  usuário com login recente (`auth_time`) e `CanSignInAsync`.
- Os **tokens pessoais** exigem sessão do próprio usuário com MFA recente.
- Bloquear um usuário comum (sem senha + lockout) também bloqueia emissão e
  renovação de tokens, porque esses caminhos usam a mesma verificação.

Caso que motivou o plano: os agentes headless do Genius autenticam como
clientes por `client_credentials`, sem usuário, e consultas a executores,
userinfo e permissões falham continuamente. O identity continua genérico: o
plano não conhece Genius nem Fleet; eles são só consumidores (seção
"Consumidores").

## Modelo

**Usuário de sistema** é um usuário do identity que **nunca entra pela tela**
e que **as aplicações enxergam como qualquer usuário**.

| Para | O que é |
|------|---------|
| Aplicações (resource servers, clientes) | Um usuário comum: `sub`, nome, avatar, claims, entitlements, papéis. Nada no token ou no userinfo o distingue de uma pessoa. |
| Identity | Um usuário **global** (sem tenant ou contexto próprio, como todo usuário do identity), marcado como "sistema", com **auditoria de criação**: quem criou, quando, de onde. |

Não há responsável obrigatório. Governança vem da auditoria (criação, emissão,
revogação e desativação ficam registradas com o operador) e das capacidades
de Management, como para qualquer usuário.

### Regras

1. **Sem entrada interativa.** Senha, logins externos (Google, GitHub,
   Facebook…), passkey, link de recuperação, reset de senha, device flow e
   MFA são recusados para usuário de sistema, em todos os caminhos e com a
   mesma resposta genérica de credencial inválida. Ele não tem senha nem
   provedor externo vinculado. A UI de Management não oferece essas ações
   para ele.
2. **"Não pode entrar" ≠ "não pode ter token".** A verificação de entrada
   interativa fica separada da verificação de emissão. Desativar o usuário
   corta as duas: nenhum token novo, credenciais revogadas e refresh tokens
   invalidados.
3. **Um cliente para cada software, não para cada usuário.** O usuário de
   sistema usa os clientes que já existem para o software que o executa,
   exatamente como uma pessoa. O `client_id` continua dizendo *qual software*;
   o `sub`, *quem*.
4. **Credencial pertence ao usuário, e o operador nunca a vê.** Um operador
   com a capacidade de Management correspondente (e MFA recente, exigido por
   todo o Management) emite para o usuário de sistema um **código de
   habilitação**.
   - O código serve para um cliente, é de uso único, curta duração e exibido
     uma única vez (popup). No banco fica só o hash
     (`systemuserenrollments`), como nos tokens de registro DCR.
   - O próprio software troca o código no `/connect/token` com o grant
     `urn:sufficit:params:oauth:grant-type:system-user-enrollment`
     (parâmetro `enrollment_code`). Recebe um refresh token de longa duração
     (`Sufficit:Identity:SystemUsers:CredentialLifetimeDays`, padrão 365)
     mais um access token, com `sub` = usuário de sistema.
   - Com prova DPoP na troca, a credencial fica presa a essa chave pela vida
     inteira (recomendado para executores).
   - Depois disso segue o caminho da credencial delegada: escopos fixos,
     prazo absoluto que o refresh não estende, revogável pela autorização.
   - Um pedido recusado por outro motivo não consome o código, e duas trocas
     simultâneas têm um único vencedor.
   - O cliente precisa da permissão `gt:` desse grant e de `refresh_token`.
5. **Mesmas regras de token.** Escopos, audiências, claims e destinos seguem
   a política normal de usuários, inclusive entitlements server-resolved. Não
   existe atalho de privilégio por ser "sistema".

## Entregas

| # | Entrega | Onde |
|---|---------|------|
| 1 | Marcação "usuário de sistema" e metadados de criação (operador, instante, correlação) | Core/Store + migração SQL canônica e aditiva |
| 2 | Recusa de entrada interativa em todos os caminhos; verificação de emissão separada da de entrada | STS |
| 3 | Emissão de credencial pelo operador (refresh token para um cliente, DPoP opcional), revogação e rotação | STS + Management API, reusando `DelegatedCredentialIssuer` |
| 4 | Management: criar, listar, desativar, emitir/revogar credencial; segredo no popup de exibição única | Management UI |
| 5 | Auditoria: criação, emissão, revogação, desativação, com operador e correlação | Management/Audit |
| 6 | Testes: login recusado em cada caminho; token e userinfo de usuário de sistema iguais aos de pessoa; desativação corta emissão e renovação; DPoP | Testes + roteiro de navegador |
| 7 | Documento de uso (`docs/usage/USAGE-SYSTEM-USERS.md`) | Docs |

As "contas de sistema" atuais (cliente sem usuário) **continuam existindo
por enquanto** para serviço puro (ex.: a ponte servidor-a-servidor do
Blazor). O Management passa a mostrar os dois tipos com nomes distintos.

> **Próximo passo, anotado pelo dono em 21/10:** rever as contas de sistema
> atuais (clientes sem usuário). Decidir se continuam existindo, se migram
> para usuário de sistema ou se ficam restritas a serviço puro. Inclui a ponte
> `sufficit-blazor-ai-bridge`.

## Consumidores (fora deste repositório)

Para referência; não fazem parte das entregas do identity.

- **Agentes do Genius (orquestrados pelo Fleet).** Decisão do dono em
  21/10: **não** usam usuário de sistema nem um por agente ou por organização.
  O agente roda sempre com o **usuário logado**, ou seja, a credencial
  delegada de quem o opera, já suportada pelo identity. O usuário de sistema
  fica para quando não houver pessoa por trás.
- **Futuro: um usuário de sistema por contexto ou cliente.** Admitido pelo
  dono, mas só depois de definir como ficam os **controles de crédito**:
  consumo e atribuição de custo de um usuário que não é pessoa. Sem prazo.
- **Clientes sem usuário que chamam o userinfo** (ex.: a ponte
  `sufficit-blazor-ai-bridge`, validada pelo sufficit-ai): continuam como
  conta de sistema de serviço. O consumidor deixa de consultar o userinfo
  para token sem usuário.

## Decisões

- Responsável humano obrigatório: **não** (decisão do dono, 21/10). Basta a
  auditoria.
- Usuário de sistema global no identity, igual a usuário comum para as
  aplicações: **sim** (decisão do dono, 21/10).
- Cliente próprio por usuário de sistema: **não**. O cliente identifica o
  software; a credencial pertence ao usuário.
- Agentes do Genius/Fleet: **usuário logado** (credencial delegada), nem
  usuário de sistema por agente nem por organização (decisão do dono, 21/10).
- Usuário de sistema por contexto ou cliente: possível no futuro, depois de
  definir os controles de crédito.

## Registro de execução

| Entrega | Commit | Verificação |
|---------|--------|-------------|
| 1, 2, 3 — banco, recusa de login, grant de habilitação | `2b3f55e` | Testes de integração: troca bearer e DPoP, userinfo vê o usuário, uso único, cliente errado, expirado, revogado, desativado; login por formulário e grant `password` recusados (o teste falha sem a trava). |
| 4, 5 — API de Management e auditoria | `cfd3ffa` | Teste ponta a ponta: criar, emitir, trocar, desativar (refresh recusado), reativar, revogar, eventos de auditoria. |
| 4 — tela | `3ed7b9b` | Roteiro Playwright no host de fixtures (criar, cliente recusado, emitir, copiar, revogar, desativar, mobile), no job de CI. |
| 7 — guia de uso | `docs/usage/USAGE-SYSTEM-USERS.md` | — |

