# Reavaliação item a item do plano (23/10/2026)

Cada item aberto de `PLAN-IDENTITY.md` foi conferido contra o código, os
testes, as atividades e a configuração de produção (somente leitura), por
seção. Resultado: 128 itens → 125.

## Saíram do plano

- **C4, SMTP `RequireTls`:** não há SMTP em produção. O e-mail sai pela fila
  do RabbitMQ (`Program.cs:164`, `EmailSenderExtensions.cs:82`), que já
  exige TLS.
- **E8, textos fixos em pt-BR:** a UI usa `.resx` (en e pt-BR); só sobram o
  nome nativo "Português" e campos de data deliberadamente em pt-BR.
- **F10, validador canônico de metadados:** já existe, um só
  (`ClientDefinitionValidator`), usado por DCR, gestão e provisionamento.
- **G4, ensaios de backup e corte:** o corte foi em agosto, com 3 restaurações
  reais registradas; o legado está aposentado.

## Reescritos

- **C2:** desbloqueado. A falha de agosto era a senha única por propósito
  (lista de sobreposição aberta com a senha nova), não o runtime; um
  certificado gerado no servidor carrega junto com os atuais.
- **F10:** o item "manter DCR desligado" contradizia a produção: DCR está
  ligado para clientes públicos anônimos desde 13/09. Virou decisão.
- **G4:** virou decisão de apagar o banco `identity_legacy`.
- **G5:** `RequireConfirmedEmail` já está ligado (padrão do código); sobra
  decidir sobre 369 contas sem e-mail confirmado e corrigir o runbook
  (consulta a uma coluna `lastlogin_at` que não existe).
- **F2:** o par `DemandAsync`/`TryWriteAuditAsync` está em ~30 arquivos, não
  em 6. **A3:** marcado como condicionado (SCIM desligado).
- **Ordem de execução:** C2 primeiro.

## Também verificado hoje

- Runtime .NET 10.0.13 (correções de segurança de 10.0.11–10.0.13) em todos
  os serviços .NET 10 dos três nós de app; o identity é o único serviço deste
  repositório entre eles.

## Decisões do dono (23/10/2026)

- **`identity_legacy` apagado:** 40 tabelas, 91 MB, nenhuma conexão; o único
  acesso era `SELECT` do usuário `identity` (revogado). O teste semanal de
  restauração dele no Databasement e a cópia restaurada no CT 3176 foram
  removidos. Restam os backups diários do Databasement por 3 dias.
- **Contas não confirmadas:** purga automática diária
  (`Management:UnconfirmedAccountPurgeDays=90` nos três nós, `6294aa6`). Na
  data, 174 das 369 eram elegíveis (sem login externo, claim ou papel; sem
  token, autorização, sessão, falha de login ou uso em 90 dias; com e-mail).
  O runbook de confirmação de e-mail foi corrigido (usava `lastlogin_at`, que
  não existe).
