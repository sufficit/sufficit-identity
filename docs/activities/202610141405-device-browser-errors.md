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

## Deploy autorizado em 14/10/2026

Após pedido explícito `deploy`, correção commitada localmente em `199e8d222fa1a64702557d1c2fb2e71af3d6798a` e publicada pelos helpers oficiais package → prepare → activate-cluster, com SUI local. Os 65 testes direcionados passaram também nesse modo; auditoria NuGet emitiu cinco avisos sobre Pkcs/Xml 10.0.11 já presentes nas dependências. Nenhuma dependência foi alterada e os lockfiles de modo pacote foram preservados.

Release `20261014T172900Z-199e8d2`, archive SHA-256 `4f2aaeb71fa1f9a168aa02bd5161fea37a21abcafe21805d543c2da3173ed6bd`. Ativação sequencial em eveo-apps, apoint-apps e castrum-apps, substituindo `20261014T023555Z-7bd6c48`; quatro arquivos de configuração herdados por nó. Sem migrations no diff desde a revisão de produção, portanto migrator não foi executado.

Gate final: três serviços ativos, mesma revisão, health/ready Healthy; certificado SHA-256 `5e858b8d138993436730db83743ac67183495e44de8e2e041e72b2882410eefb` e JWKS SHA-256 `85d43862afae2e2eea21c6668aa9ec34fa0c029ac906cd0eaee9122847aed769`, preservados do baseline. Sem rollback.

Smoke HTTP público em https://identity.sufficit.com.br: POST de device verification sem antiforgery válido (rejeitado antes de qualquer aprovação) retornou 400 HTML para navegação humana e 400 JSON para máquina. Título em português, ausência de código/descrição, no-store/no-referrer e três estilos CSS 200 conferidos; discovery 200 com issuer correto. O invalid_grant foi exercitado nos testes isolados; não foi usado device code real de usuário em produção. Sem navegador real nesta etapa.

Commit e documentação permanecem locais, sem push. Plano temporário concluído e removido; este registro guarda evidências e release efetivamente publicada.
