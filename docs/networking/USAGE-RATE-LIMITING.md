# Rate limit por operação e respostas 429

O host aplica janelas fixas por **operação e IP efetivo**, sem fila, antes da autenticação. O IP deve ser resolvido pela cadeia de [proxies confiáveis](USAGE-TRUSTED-PROXIES.md). Os contadores são locais a cada réplica; esta configuração não implementa uma cota global do cluster.

## Cotas independentes

Configuração em `Sufficit:Identity:RateLimit`:

| Grupo | Rotas | Padrão por IP | Configuração |
| --- | --- | --- | --- |
| Token | POST `/connect/token`, incluindo `/mtls` | 30 / 60 s | `TokenPermitLimit`, `TokenWindowSeconds` |
| Introspecção | POST `/connect/introspect`, incluindo `/mtls` | 300 / 60 s | `IntrospectionPermitLimit`, `IntrospectionWindowSeconds` |
| Interação | POST de login, recuperação, cadastro de usuário, passkeys, confirmação de dispositivo, consentimento, logout e conclusão CIBA | 30 / 60 s | `InteractivePermitLimit`, `InteractiveWindowSeconds` |
| Início device/CIBA | POST `/connect/deviceauthorization`, `/bc-authorize` | 30 / 60 s | `PermitLimit`, `WindowSeconds` |
| Registro de cliente | POST `/connect/register` | 30 / 60 s | `PermitLimit`, `WindowSeconds` |
| Outros protocolos | Demais POST `/connect/*` | 30 / 60 s | `PermitLimit`, `WindowSeconds` |
| PAR | POST `/connect/par` | 30 / 60 s | `PushedAuthorizationPermitLimit`, `PushedAuthorizationWindowSeconds` |
| Consulta de dispositivo | GET `/connect/device/info` | 12 / 60 s | `DeviceInformationPermitLimit`, `DeviceInformationWindowSeconds` |
| Administração / SCIM | Prefixo da API de Management e `/scim` | 600 / 60 s | `AdministrativePermitLimit`, `AdministrativeWindowSeconds` |
| Administração em lote | Provisionamento e revogação das sessões de um usuário | 30 / 60 s | `AdministrativeBulkPermitLimit`, `AdministrativeBulkWindowSeconds` |

Os overrides de token e interação são nullable: quando omitidos ou `null`, herdam `PermitLimit` e `WindowSeconds`. Os demais grupos da tabela mantêm seus próprios contadores mesmo quando usam os mesmos valores de configuração. A introspecção tem padrão próprio de 300/60 s para acomodar validações entre serviços sem consumir a cota humana.

Esgotar token ou introspecção não bloqueia a confirmação do dispositivo nem o login. A limitação continua ativa dentro de cada grupo: clientes que compartilham um IP também compartilham a cota daquela operação. `client_id` enviado em formulário, query string ou cabeçalho não é uma identidade validada e não cria uma partição. Aliases mTLS compartilham a cota da operação; caminhos desconhecidos usam um grupo fixo. O bloqueio por tentativas de senha por conta continua independente.

## Navegação humana e APIs

A regra detalhada, exemplos com Playwright e orientação para novos erros estão em [Classificação de navegação e API](USAGE-BROWSER-API-CLASSIFICATION.md).

Todo 429 inclui `Retry-After` em segundos, arredondado para cima (mínimo 1), `Cache-Control: no-store` e `Pragma: no-cache`. Quando o limiter fornece o tempo restante, esse valor é utilizado; caso contrário, usa-se a janela da operação rejeitada.

Com a UI pública embutida, rotas interativas conhecidas retornam HTML quando o pedido prefere explicitamente `text/html` a `application/json`. Se presentes, `Sec-Fetch-Mode` deve ser `navigate` e `Sec-Fetch-Dest`, `document`; `X-Requested-With` impede HTML. User-Agent Chrome, sozinho, não identifica navegação. A detecção escolhe somente a apresentação; não concede confiança ou autorização.

A página reutiliza `AuthorizationError.razor` e os estilos do erro de autorização introduzido no commit `1b93ca3` (9 de setembro de 2026). Explica a pausa, mostra o tempo de espera e orienta voltar ao aplicativo/página de origem. Não reflete mensagens, códigos ou URLs recebidos, não redireciona para `returnUrl`, não depende de JavaScript/circuito/banco e não reenvia formulários. O único destino de recuperação é `/`.

O idioma vem de `Accept-Language`, respeitando a prioridade: variantes `pt` são apresentadas em `pt-BR`, variantes `en` em `en-US`. Sem idioma suportado, o padrão é português. A resposta também declara `Content-Language`.

Token, introspecção, PAR, registro de cliente, device authorization, passkeys e demais APIs mantêm JSON, inclusive quando enviam cabeçalhos de navegador. Requisições fetch/XHR ou de preferência ambígua também recebem JSON. Hosts sem UI pública embutida mantêm JSON. OAuth preserva `error: temporarily_unavailable`; outras rotas recebem `error: rate_limit_exceeded`. Ambos incluem `error_description` estável em inglês. Consumidores devem interpretar o status, o campo `error` e `Retry-After`, evitando repetição imediata.

## Verificação

`RateLimiterServiceCollectionExtensionsTests` verifica isolamento das operações, IPs, aliases e tentativas de variar `client_id`/rota. `BrowserRateLimitErrorTests` exercita o middleware real em HTTP, negociação, idiomas, formulários de senha/2FA/recuperação, JSON, ausência de reflexão e tempo de espera. `BrowserAuthorizationErrorTests` cobre a tela de autorização reutilizada.

Executar a suíte: `dotnet test src/tests/Sufficit.Identity.Tests.csproj`. Para capturar o HTML dos testes de apresentação, definir `SUFFICIT_AUTH_PREVIEW_DIR` para um diretório temporário. A ativação em produção exige publicar o host atualizado; editar este arquivo ou o template não altera os serviços em execução.
