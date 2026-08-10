# Atividade concluída — alinhamento dos chips da auditoria

**Data:** 2026-08-08
**Status:** concluída, testada e validada

## Entrega

- Os chips de resultado da tela `/management/audit` usam um layout flexível de
  largura integral dentro das células da tabela, evitando que a regra genérica
  de spans deixe o conteúdo preso à esquerda.
- O texto dos estados fica centralizado dentro do chip e o chip fica
  centralizado na coluna **Resultado** em telas largas.
- No modo mobile, a legenda da linha permanece alinhada à esquerda e o chip
  fica centralizado somente na área de valor, sem alterar a ordem de leitura.

## Validação

- Detector Impeccable de layout executado no CSS da Management UI: nenhum
  apontamento.
- `dotnet build Sufficit.Identity.sln --no-restore`: passou quando a correção
  foi validada; uma alteração paralela posterior em `Branding.razor` agora
  interrompe o build por declarar `PreviewStyle` duas vezes.
- `dotnet test Sufficit.Identity.sln --no-restore --no-build`: 531 aprovados,
  1 ignorado, 532 total na validação do patch.
