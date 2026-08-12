# Tokens temporários de Management pré-preenchidos por URL

Horário da implementação local: 2026-08-12 17:38:46 -03.

## Objetivo

Permitir que um operador autenticado abra uma solicitação administrativa já
preenchida, confira os limites e gere um Bearer temporário com um clique. O
fluxo atende tarefas ocasionais em qualquer recurso do Management, enquanto o
token temporário anterior continua restrito ao provisionamento de manifestos.

## Contrato da URL

Rota:

```text
/management/tokens
```

Parâmetros de query string:

- `action=issue`: apresenta a solicitação como preparada para emissão;
- `purpose`: finalidade auditável, limitada a 120 caracteres;
- `lifetimeSeconds`: validade de 60 segundos até o limite configurado, nunca
  superior a 3600 segundos;
- `capability`: capability repetível;
- `capabilities`: alternativa em CSV.

Exemplo para editar clientes:

```text
https://identity.sufficit.com.br/management/tokens?action=issue&purpose=Atualizar%20clientes%20Hermes%20e%20Symposium&lifetimeSeconds=900&capability=identity.clients.read&capability=identity.clients.update
```

Abertura da URL não emite token. O operador precisa estar autenticado, cumprir
MFA, possuir `identity.operator-tokens.issue` e confirmar em **Confirmar e gerar
token**. Parâmetros inválidos ou capabilities não concedidas bloqueiam a ação e
aparecem de forma explícita na tela.

## Limites de segurança

- scope OAuth fixo: `identity.management`;
- reference token de curta duração, com máximo rígido de uma hora;
- somente capabilities que o operador já possui;
- papel `administrator` não é incorporado ao token;
- `identity.operator-tokens.issue` e `identity.operator-tokens.revoke` não são
  delegáveis;
- outro token temporário não pode emitir um novo token;
- valor do Bearer é exibido somente na resposta de emissão;
- listagem posterior contém apenas metadados do próprio operador;
- emissão e revogação são auditadas sem persistir o segredo em logs ou eventos.

## Configuração

O recurso permanece desabilitado por padrão:

```text
Sufficit__Identity__Management__TemporaryOperatorToken__Enabled=false
```

Para o ambiente operacional aprovado, habilitar explicitamente e manter MFA:

```text
Sufficit__Identity__Management__RequireMfa=true
Sufficit__Identity__Management__TemporaryOperatorToken__Enabled=true
```

## Evidência local

- build da UI Management: 0 erros, 0 avisos;
- build Release da solução: 15 projetos, 0 erros, 0 avisos;
- testes direcionados: 4 aprovados;
- suíte completa: 669 aprovados, 0 avisos;
- detector visual executado; apontou somente padrões preexistentes do tema
  global (`Inter` e um acento lateral antigo), sem ocorrência nova nesta tela;
- `git diff --check`: sem erros de whitespace.

O trabalho anterior sobre validade de tokens do Hermes e Symposium foi
preservado separadamente em
`docs/activities/202608121721-hermes-symposium-token-lifetimes-handoff.md`.
