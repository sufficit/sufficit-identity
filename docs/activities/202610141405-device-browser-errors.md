# Erros de device code no navegador

Solicitação: usar a mesma tela amigável dos outros erros quando uma pessoa encontra `invalid_grant` ao confirmar device code indisponível/expirado em `/connect/device`.

## Alterações e decisões

- A classificação compartilhada de navegação inclui a rota exata `/connect/device`, em GET e POST. Exige preferência explícita por HTML e rejeita fetch/XHR e iframes; endpoints de token, deviceauthorization e device/info continuam excluídos.
- A UI pública registra um filtro MVC para erros HTTP 400 do DeviceController. Esses erros podem ser BadRequestObjectResult locais e já escreveriam JSON antes de status pages, sem depender de uma resposta OpenIddict no contexto.
- O filtro reutiliza AuthorizationError.razor integralmente: título, explicação, orientação para reiniciar no aplicativo, ação de início e CSS existentes. Ledger/referência visual: componente atual e pedido explícito de manter o padrão das outras telas; sem decisões novas de layout/tokens.
- Resposta mantém 400, no-store/no-cache e no-referrer. Não reflete códigos, descrições técnicas ou URLs; não repete nem aprova a solicitação rejeitada.
- Registro do filtro fica no módulo público embarcado; clientes de API mantêm JSON e hosts sem UI não recebem o filtro.

## Validação

Regressão HTTP: host SQLite isolado, emissão de device authorization com lifetime negativo, login e antiforgery válidos, confirmação POST devolvendo invalid_grant para máquina; HTML amigável para navegação humana. Antes da correção, o caso HTML falhava recebendo application/json. Casos finais verificam preferência HTML, JSON explícito, wildcard e JSON preferido, status, conteúdo localizado, CSS/ação existentes e ausência de user code/descrição.

Comando: `dotnet test src/tests/Sufficit.Identity.Tests.csproj -p:SufficitUseLocalSui=false --filter 'FullyQualifiedName~BrowserAuthorizationErrorTests|FullyQualifiedName~BrowserRateLimitErrorTests|FullyQualifiedName~DeviceFlowTests|FullyQualifiedName~PublicUiModuleCompositionTests|FullyQualifiedName~ProgramPipelineOrderTests' --verbosity quiet`.

Resultado final: 65 testes passaram, sem warnings. `git diff --check` passou.

Entrega local; sem commit, push ou deploy. Renderização SSR conferida pelos testes HTTP; não houve validação em navegador real nem em produção.
