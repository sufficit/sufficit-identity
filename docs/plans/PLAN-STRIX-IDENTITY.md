# Plano de avaliação do Sufficit Identity com Strix

## Estado

- [x] Confirmar o repositório `sufficit/strix` e seu modo de operação.
- [x] Confirmar o OIDC público do `identity.sufficit.com.br`.
- [x] Confirmar os pré-requisitos do ambiente de execução.
- [x] Obter credencial de LLM para o CLI Strix e registrar o escopo autorizado.
- [x] Executar uma varredura inicial não destrutiva em modo `quick` (execução parcial preservada; sem conclusão limpa).
- [x] Disponibilizar localmente o CLI corrigido com normalização dos argumentos opcionais do Caido.
- [ ] Concluir uma varredura profunda com o provedor de LLM responsivo.
- [ ] Revisar os achados e separar falsos positivos de vulnerabilidades reproduzíveis.
- [ ] Corrigir somente itens aprovados e executar nova varredura de validação.

## Resultado da descoberta (2026-08-09)

O Strix é um pentester autônomo que valida achados com provas de conceito. Há dois modos:

1. **CLI local:** requer Docker funcional e uma chave de LLM (`STRIX_LLM`/`LLM_API_KEY`).
2. **Plataforma gerenciada:** requer um `STRIX_API_TOKEN`, sem Docker local.

O Docker local foi instalado e validado com `hello-world`. O CLI Strix 1.5.2 e as imagens
sandbox `ghcr.io/usestrix/strix-sandbox:1.3.0` e `ghcr.io/usestrix/strix-sandbox:1.2.0`
estão disponíveis. A credencial do endpoint OpenAI-compatível foi fornecida por canal
seguro e não é armazenada neste repositório.

O endpoint público respondeu corretamente durante a checagem:

- `GET https://identity.sufficit.com.br/health` → `200`;
- `GET https://identity.sufficit.com.br/health/ready` → `200`;
- `GET https://identity.sufficit.com.br/.well-known/openid-configuration` → `200`;
- o metadata OIDC anuncia `/connect/deviceauthorization` e `/connect/token`.

## Primeiro scan executado (2026-08-09)

- Run: `identity-sufficit-com-br_9dbe`.
- Alvo: `https://identity.sufficit.com.br`.
- Modo: `quick`, sandbox `1.2.0`, sem telemetria Strix.
- Reconhecimento concluído e agentes especializados iniciados para OIDC, tokens,
  device authorization, sessão/CSRF, rate limiting e provedores externos.
- Artefatos preservados em `/tmp/strix_runs/identity-sufficit-com-br_9dbe`:
  `run.json`, `strix.log` e `findings.sarif`.
- Resultado SARIF no momento da interrupção: **0 resultados**. Isso não deve ser
  interpretado como aprovação de segurança: a execução foi interrompida após 232
  requisições ao LLM porque entrou em ciclos longos sem novas evidências.
- Limitação observada no sandbox: o proxy Caido falhou repetidamente ao paginar
  requisições e sitemap (`Invalid ID format` / `Failed to parse cursor`). Esses erros
  são do adaptador do Strix/Caido e reduziram a cobertura; não são achados do Identity.
- A imagem `1.3.0` foi descartada para o scan por falha de inicialização do Caido
  (`Address already in use`); a imagem `1.2.0` iniciou corretamente.

Após o encerramento, os smoke checks públicos permaneceram normais:
`/health`, `/health/ready` e `/.well-known/openid-configuration` responderam `200`.
O container de execução do Strix foi removido; os artefatos do run permanecem em
`/tmp/strix_runs/identity-sufficit-com-br_9dbe` para auditoria.

### Próximo ciclo obrigatório

Reexecutar uma varredura profunda com o CLI corrigido e um provedor de LLM
responsivo. Só depois revisar os achados e classificar o serviço como aprovado,
pendente ou vulnerável.

## Repetição controlada (2026-08-09)

Foi repetido um ciclo `quick` com `--max-turns 5` e orçamento controlado usando o
sandbox `1.2.0`. A execução `identity-sufficit-com-br_caca` foi interrompida após
16 requisições ao LLM porque reproduziu os mesmos erros do Caido ao listar/paginar
`requests` e `sitemap`. O SARIF permaneceu com **0 resultados**, sem evidência
reproduzível de vulnerabilidade, mas a cobertura continua insuficiente para uma
aprovação de segurança. O tag `latest` aponta para o mesmo digest da imagem `1.3.0`,
que já havia falhado na inicialização do Caido.

## Causa raiz da falha do Caido (2026-08-09)

A análise dos argumentos registrados no `agents.db` confirmou que o modelo
OpenAI-compatível chamava as ferramentas com `scope_id: "null"`, `parent_id:
"null"` e `after: "null"`. Esses valores são strings, não nulos JSON. O SDK do
Caido então tenta decodificar `"null"` como ID inteiro ou cursor opaco e retorna
`Invalid ID format, should be an i32` / `Failed to parse cursor`.

A correção aplicada no checkout local do Strix (`/tmp/strix.FRBB2J/repo`) é
normalizar `"null"`, `"none"` e string vazia para `None` na fronteira das
ferramentas `list_requests`/`list_sitemap` e novamente na camada `caido_api`.
Também foram adicionados testes unitários para preservar cursores e IDs reais.
O patch foi compilado com sucesso e validado com `17 passed` na suíte
`tests/test_proxy_client.py`. A correção foi disponibilizada no CLI local oficial
em `/home/hugodeco/.strix/bin/strix`; o binário standalone anterior foi preservado
em `/home/hugodeco/.strix/bin/strix.pre-null-normalization-20260809205239`.
O entrypoint agora usa o ambiente persistente
`/home/hugodeco/.strix/venv-patched-1.5.2`, com o checkout corrigido em
`/home/hugodeco/.strix/src/strix-1.5.2-null-normalization`; a instalação não depende
mais do diretório temporário `/tmp`.

## Validação com CLI corrigido (2026-08-09)

- Run: `identity-sufficit-com-br_191a`.
- CLI local com a normalização aplicada; sandbox `1.2.0`.
- Status: `completed`, 20 requisições ao LLM, SARIF com **0 resultados**.
- Nenhum erro `Invalid ID format`, `Failed to parse cursor`, `list_requests failed`
  ou `list_sitemap failed` apareceu no log.
- O ciclo foi `quick` e limitado a 10 turnos; o relatório classifica o resultado
  como reconhecimento/baseline, não como pentest profundo. A cobertura restante
  deve ser executada em modo `deep` com o CLI corrigido.

## Revalidação profunda controlada (2026-08-09)

- Run: `identity-sufficit-com-br_8952`.
- CLI: `/home/hugodeco/.strix/bin/strix` (patch de normalização ativo e persistente), sandbox `1.2.0`.
- Modo: `deep`, orçamento máximo de US$ 2, 30 turnos por agente, sem telemetria.
- Foram concluídas 56 chamadas ao LLM; o SARIF parcial contém **0 resultados**.
- Não houve `Invalid ID format`, `Failed to parse cursor`, `list_requests failed`,
  `list_sitemap failed` ou exceções no log.
- A execução foi interrompida de forma controlada após o agente ficar sem progresso
  em uma chamada do provedor. Portanto, o resultado não é aprovação de segurança:
  a cobertura profunda precisa de um ciclo concluído.
- O contêiner do Strix foi encerrado e não há processo de scan pendente. Os checks
  posteriores permaneceram normais: `/health`, `/health/ready` e o metadata OIDC
  retornaram `200`.

## Escopo sugerido

Com autorização para testar o serviço próprio, começar pelo domínio público:

```bash
strix -n \
  --target https://identity.sufficit.com.br \
  --scan-mode quick \
  --instruction-file docs/security/RUNBOOK-STRIX-IDENTITY-SCOPE.md
```

O primeiro ciclo deve priorizar autenticação/autorização, OAuth/OIDC, device flow,
consentimento, revogação, CSRF, rate limiting, headers de segurança e exposição de
informações. Não incluir testes destrutivos, criação em massa de contas, envio de e-mail,
alteração de dados ou exploração de infraestrutura fora do domínio.

## Critérios para iniciar

- credencial Strix local/gerenciada fornecida por canal seguro;
- confirmação de que o alvo é produção e janela de teste autorizada;
- limite de orçamento/tempo do scan definido;
- plano de rollback e contato operacional disponíveis;
- artefatos do Strix preservados para revisão (`run.json`, relatório e SARIF).
