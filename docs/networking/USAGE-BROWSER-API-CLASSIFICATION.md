# Classificação de navegação, API e automação (Playwright)

Referência para a **identificação de navegador/API na apresentação de erros** do Sufficit Identity. Consulte este documento ao reutilizar a tela amigável em outro erro. Comportamento conferido no código em 10/09/2026.

## O que o sistema identifica

A classificação responde: **“esta requisição, nesta rota, pede uma página HTML de navegação?”**. Ela não comprova que o solicitante é uma pessoa e não identifica Playwright como uma terceira categoria.

Um navegador controlado por Playwright pode enviar a mesma navegação de uma pessoa e receber a mesma página. Uma pessoa usando uma aplicação no Chrome pode provocar uma chamada fetch de API e receber JSON. Um script que reproduza os cabeçalhos aceitos também pode obter HTML em uma rota elegível.

O resultado escolhe somente a apresentação do erro. Não autentica, não autoriza, não reconhece bots, não altera a cota e não confere confiança a IPs ou cabeçalhos de proxy. Não existe decisão baseada em User-Agent, nome Chrome/HeadlessChrome/Playwright, `navigator.webdriver`, cookies de sessão ou impressão digital do navegador.

## Ordem da decisão

1. Verificar se o método e a rota são elegíveis para aquele tipo de erro. Rotas de protocolo/API não devem se tornar páginas apenas porque pediram HTML.
2. Verificar os cabeçalhos de navegação e a preferência por HTML usando `BrowserNavigationRequest.PrefersHtmlDocument`.
3. Se as condições forem atendidas e o renderizador estiver disponível, apresentar a página. Caso contrário, manter a resposta apropriada à API/protocolo.

O helper retorna um booleano, não uma identidade, pontuação ou enumeração `humano/api/playwright`.

### Regra exata dos cabeçalhos

| Entrada | Condição atual |
| --- | --- |
| `Sec-Fetch-Mode` | Se não vazio, deve ser exatamente `navigate`. Outro valor rejeita HTML. |
| `Sec-Fetch-Dest` | Se não vazio, deve ser exatamente `document`. `iframe`, `empty` e outros valores rejeitam HTML. |
| `X-Requested-With` | A presença do cabeçalho rejeita HTML, independentemente do valor. |
| `Accept` | Deve incluir `text/html` com qualidade positiva e **maior** que a qualidade de `application/json`. |
| `User-Agent` | Não consultado. |
| `Accept-Language` | Não participa da classificação; escolhe o idioma depois da decisão de renderizar o 429. |

A ausência de `Sec-Fetch-*` não impede HTML: isso permite clientes que não enviam esses cabeçalhos. Logo, o sistema não exige prova de navegação emitida pelo navegador.

No `Accept`, a qualidade `q` omitida vale 1. O algoritmo utiliza a maior qualidade declarada para cada um dos dois tipos exatos, `text/html` e `application/json`, sem diferenciar maiúsculas/minúsculas nesses tipos. Se um deles não está presente, sua qualidade é zero. Empate favorece a resposta de API. Ausência de `Accept`, somente `*/*`, ou `text/html;q=0` não seleciona HTML. Se o parser lança `FormatException`, o helper retorna falso.

Esta é uma regra deliberadamente restrita de apresentação, não um negociador completo de todos os media types: `application/xhtml+xml`, `application/problem+json`, `application/*` e outros tipos não entram na comparação entre HTML e JSON. Para solicitar a resposta de API de forma inequívoca, use `Accept: application/json`.

## Onde se aplica hoje

### Erros de autorização

`BrowserNavigationRequest.IsHtmlNavigation` aceita somente GET nas rotas exatas `/connect/authorize` e `/connect/endsession`, sem diferenciar maiúsculas/minúsculas. Em seguida aplica a regra de cabeçalhos.

`BrowserAuthorizationErrors` usa essa classificação no middleware de páginas de status e renderiza somente quando há erro OpenIddict. A apresentação não substitui o encaminhamento de erro para um redirect URI válido do cliente. O STS também possui um fallback específico para erro local de autorização sem o middleware de páginas de status; isso não torna todos os erros de um host sem UI elegíveis para HTML.

### Rate limit (HTTP 429)

`BrowserRateLimitErrors.IsHtmlNavigation` aceita GET ou POST nas seguintes rotas exatas e aplica a mesma regra de cabeçalhos:

- `/connect/device`, `/connect/authorize`, `/connect/endsession`, `/connect/ciba/complete`;
- `/account/login`, `/account/login/password`, `/account/login/2fa`, `/account/login/recoverycode`;
- `/account/forgotpassword`, `/account/resetpassword`, `/account/register`, `/account/externallogincallback`.

Subcaminhos ou barra final não são automaticamente incluídos nessa lista. A elegibilidade para apresentar HTML não significa que toda requisição nessas rotas será limitada: a política de cotas decide separadamente se há um 429.

O renderizador de 429 é registrado somente quando a UI pública está embutida. Sem ele, a resposta continua JSON. Token, introspecção, PAR, registro de cliente, device authorization e APIs de passkeys ficam fora da lista, mesmo com cabeçalhos de navegação.

A página reutiliza `AuthorizationError.razor`, com recursos e estilos existentes. O status continua 429, com `Retry-After`, `Cache-Control: no-store` e `Pragma: no-cache`. APIs OAuth recebem `temporarily_unavailable`; outras rotas recebem `rate_limit_exceeded`. Veja [cotas e respostas 429](USAGE-RATE-LIMITING.md).

## Exemplos de classificação

A tabela descreve a escolha de apresentação **quando já existe uma rejeição 429**, com UI pública embutida. Os cabeçalhos não mencionados são ausentes.

| Pedido | Resultado | Motivo |
| --- | --- | --- |
| POST `/connect/device`, `Accept: text/html`, modo `navigate`, destino `document` | HTML | Navegação elegível. |
| Mesmo pedido sem `Sec-Fetch-*` | HTML | Os cabeçalhos de navegação não são obrigatórios. |
| Mesmo pedido produzido por Playwright | HTML | Automação não muda a regra. |
| POST `/connect/device`, `Accept: application/json` | JSON | Preferência explícita de API. |
| POST `/connect/device`, `Accept: */*`, User-Agent Chrome | JSON | User-Agent não compensa a ausência de preferência HTML. |
| POST `/connect/device`, `Accept: text/html,application/json` | JSON | Qualidades iguais. |
| POST `/connect/device`, `Accept: text/html;q=0.8,application/json;q=0.5` | HTML | HTML tem qualidade maior. |
| POST `/connect/device`, `Accept: text/html`, modo `cors`, destino `empty` | JSON | Não é a navegação aceita pelo helper. |
| POST `/connect/device`, `Accept: text/html`, destino `iframe` | JSON | Documento embutido não é elegível. |
| POST `/connect/device`, `Accept: text/html`, `X-Requested-With: XMLHttpRequest` | JSON | Cabeçalho de chamada programática presente. |
| POST `/connect/token`, `Accept: text/html`, modo `navigate`, destino `document` | JSON | Rota de protocolo excluída. |
| POST `/account/passkeys/assertion`, `Accept: text/html` | JSON | API de passkeys excluída. |

## Playwright: como testar sem inferir o solicitante

Para testar a experiência visual, navegue com uma página do navegador controlado e use o fluxo/formulário correspondente à rota. Inspecione a requisição efetivamente enviada: ela precisa atender às mesmas condições da navegação manual. Executar em modo headless não muda o algoritmo do Identity.

Para testar APIs por uma ferramenta de automação, envie explicitamente `Accept: application/json` e confira o status, `Content-Type`, `error` e `Retry-After`. O nome da ferramenta não deve determinar o formato esperado. Se uma requisição programática reproduzir cabeçalhos de navegação e chamar uma rota interativa, poderá receber HTML.

Não acrescente tratamento especial que dê acesso, retire rate limit ou escolha uma página com base no nome “Playwright”. Os testes devem verificar o contrato de rota/cabeçalhos, incluindo uma chamada de token que peça HTML e ainda receba JSON.

## Idioma e segurança da página 429

Depois de selecionar HTML, `ResolveCulture` percorre `Accept-Language` por qualidade decrescente, ignorando entradas com qualidade zero. O primeiro idioma suportado vence: `pt`/variantes regionais usam `pt-BR`; `en`/variantes usam `en-US`. Sem preferência suportada, ou com falha de parsing, o padrão é `pt-BR`. A resposta declara `Content-Language` e o atributo `lang` do HTML.

Exemplos: `en-GB,en;q=0.9` → inglês; `pt;q=0.3,en;q=0.8` → inglês; `en;q=0,pt;q=0.5` → português. Esse resolvedor específico do 429 não deve ser confundido com a configuração global de localização de outras páginas.

A tela não reflete `error_description`, códigos, tokens, query strings ou URLs de retorno recebidos. O único link de recuperação é `/`. Não redireciona para uma origem informada pelo chamador e não reenvia POST automaticamente. O conteúdo SSR não depende de JavaScript, circuito Blazor, autenticação ou consulta ao banco para apresentar a mensagem.

## Como reutilizar em outro erro

- Reutilizar `PrefersHtmlDocument` para os cabeçalhos e definir explicitamente os métodos/rotas elegíveis do novo erro. Não ampliar globalmente a lista do 429 por conveniência.
- Preservar o status HTTP, os cabeçalhos necessários e o contrato de erro das APIs. A página muda a apresentação, não o resultado da operação.
- Reutilizar os componentes/estilos e recursos de tradução existentes. Não copiar mensagens técnicas recebidas diretamente para o HTML.
- Registrar o renderizador apenas no host que dispõe da UI; manter um fallback apropriado para hosts sem ela.
- Testar rota humana, rota de API com cabeçalhos HTML, fetch/XHR, iframe, empate/ausência de `Accept`, idiomas e ausência de reflexão. Conferir também que a regra de segurança/cota permaneceu igual.

## Código e testes de referência

| Responsabilidade | Fonte |
| --- | --- |
| Cabeçalhos e rotas de autorização | [BrowserNavigationRequest.cs](../../src/sts/ErrorPages/BrowserNavigationRequest.cs) |
| Renderização de erro de autorização | [BrowserAuthorizationErrors.cs](../../src/server/BrowserAuthorizationErrors.cs) |
| Fallback local de autorização no STS | [BrowserAuthorizationErrorPage.cs](../../src/sts/ErrorPages/BrowserAuthorizationErrorPage.cs) |
| Rotas, idioma e renderização do 429 | [BrowserRateLimitErrors.cs](../../src/server/BrowserRateLimitErrors.cs) |
| Escolha entre HTML e JSON no 429 | [IdentityRateLimitPolicy.cs](../../src/server/IdentityRateLimitPolicy.cs) |
| Componente SSR compartilhado | [AuthorizationError.razor](../../src/ui/Sufficit.Identity.UI/Components/AuthorizationError.razor) |
| Contratos do 429 em HTTP | [BrowserRateLimitErrorTests.cs](../../src/tests/BrowserRateLimitErrorTests.cs) |
| Regressão dos erros de autorização | [BrowserAuthorizationErrorTests.cs](../../src/tests/BrowserAuthorizationErrorTests.cs) |

Para executar os testes relacionados:

```bash
dotnet test src/tests/Sufficit.Identity.Tests.csproj --filter 'FullyQualifiedName~BrowserRateLimitError|FullyQualifiedName~BrowserAuthorizationError'
```

A classificação não realiza consultas externas nem consultas de banco. O contrato descrito aqui foi publicado no Identity; esta referência não afirma adoção automática em outros projetos.
