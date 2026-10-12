# Autenticação de dispositivo em uma única janela

## Problema e mudança
As capturas do usuário mostravam o Genius abrindo /device/launch, seguido de
um clique em Abrir autenticação para abrir um segundo popup. O launcher foi
introduzido para facilitar fechamento automático, mas acrescentava uma etapa
redundante ao login.

DeviceBrowserLaunch agora responde HTTP 302 para /connect/device com o código
público validado e launch_mode=popup. O destino é relativo e fixo; parâmetros
extras não são encaminhados. Mantidos no-store, no-referrer e COOP.
Login, consentimento explícito, tickets protegidos e polling OAuth permanecem
nos endpoints existentes. Genius instalado já usa essa rota e recebe a mudança
sem precisar de atualização do cliente. Nenhum arquivo Genius foi alterado.

## Decisões e referências
- Capturas e pedido do usuário: remover clique intermediário e popup filho.
- Telas existentes Identity: preservar apresentação de login e consentimento.
- Fechamento de aba externa depende do navegador; o fallback manual existente
  permanece. Prioridade é autorização em uma janela.
- Componentes/assets do launcher antigo não foram removidos nesta correção;
  a rota não os renderiza mais.

## Validação
- Antes do fix: 3 casos de regressão falharam (esperado 302, recebido 200);
  4 casos de código inválido passaram.
- Após o fix: 37 testes passaram, zero warnings, incluindo
  DeviceBrowserLaunchTests, DeviceFlowTests, PublicUiModuleCompositionTests
  e CspHeaderTests.
- Comando: dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore
  --filter "FullyQualifiedName~DeviceBrowserLaunchTests|FullyQualifiedName~DeviceFlowTests|FullyQualifiedName~PublicUiModuleCompositionTests|FullyQualifiedName~CspHeaderTests" --verbosity quiet.
- git diff --check passou. Compilação realizada pelo dotnet test.
- Não houve validação com sessão de produção nem deploy. A remoção da tela
  intermediária foi validada pela resposta HTTP 302 sem corpo, não por um
  novo login no navegador.

## Entrega
Branch local fix/device-single-window, worktree
/mnt/sufficit/sufficit-identity/.worktrees/codex-device-single-window-20261012.
Contrato atualizado em docs/design/DESIGN-DEVICE-FLOW-POPUP.md.
