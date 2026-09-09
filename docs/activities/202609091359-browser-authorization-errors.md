# Erros amigáveis para navegação OAuth

Implementado localmente sobre main 637c35b, preservando cinco package locks preexistentes. Sem deploy, push ou mudança em credenciais.

`BrowserAuthorizationErrors` integra status pages antes da autenticação, somente quando o host possui UI pública embutida. `EnableStatusCodePagesIntegration` do OpenIddict delega a apresentação quando essa feature existe no request; demais chamadas mantêm respostas originais.

Condições: GET em `/connect/authorize` ou `/connect/endsession`, Accept explícito de text/html com qualidade positiva e superior a application/json; Sec-Fetch-Mode navigate e Sec-Fetch-Dest document quando presentes. Não usa User-Agent. XHR, iframe, wildcard e APIs não recebem HTML. Cabeçalhos classificam apresentação, nunca autorização.

`AuthorizationError.razor` é SSR estático, sem circuito ou consulta ao banco. Usa estilos existentes do Identity e CSS responsivo específico. Não reflete error_description, redirect_uri ou request_uri, não redireciona automaticamente e preserva a rejeição HTTP. Cache-Control no-store e Referrer-Policy no-referrer. Links fixos para início do Identity e Blazor, sem retorno controlado pela requisição.

Validação:

- `dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore --filter 'FullyQualifiedName~BrowserAuthorizationErrorTests|FullyQualifiedName~AuthorizationCodeFlowTests|FullyQualifiedName~FapiJarmTests' --verbosity quiet -p:SufficitUseLocalSui=true`: 43 testes aprovados, zero warnings.
- PAR emitido e autorizado em TestServer/SQLite; replay gera 400/ID2013 para cliente técnico e 400/HTML amigável para navegação. APIs continuam JSON inclusive com headers de navegador.
- Playwright: HTML real de SSR em 1280/390 px, gap 12 px, botões 44 px e sem overflow. Capturas `/tmp/sufficit-auth-guidance-preview/identity-error-*.png`.
- Sem login de usuário real, teste de conta de produção ou alteração de política MFA. Layout e testes correspondentes do consumidor documentados em `sufficit-blazor/docs/activities/202609091359-authentication-guidance.md`.
