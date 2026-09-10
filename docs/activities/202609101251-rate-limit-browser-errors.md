# Rate limit por operação e erro amigável no navegador

## Objetivo e ponto de partida

Corrigir a disputa de cota entre tráfego de protocolo e confirmação/login, e apresentar um 429 compreensível ao usuário no idioma do navegador, reutilizando a tela existente.

A investigação de 10/09/2026 mostrou IPs finais corretos nos logs; o bloqueio observado na confirmação do dispositivo às 12:33 BRT veio do mesmo IP com rejeições em token imediatamente antes. O limiter agrupava POSTs de token, introspecção e interação na mesma partição por IP. A introspecção também concentrava centenas de rejeições no período analisado. Não foi necessário ampliar redes confiáveis ou ignorar a cadeia de proxies.

O checkout já continha as implementações de proxies confiáveis e sincronização NATS. Foram preservadas. Nenhum servidor de produção foi modificado nesta implementação.

## Alterações e decisões

- `IdentityRateLimitPolicy`: grupos fixos de token, introspecção, interação, início de device/CIBA, registro de cliente, PAR e demais protocolos. Token/introspecção não consomem a cota de login/confirmação. Aliases mTLS compartilham o grupo original; caminhos desconhecidos não criam partições livres.
- `RateLimitOptions`: overrides opcionais para token/interação, herdando os limites anteriores quando nulos. Introspecção independente, padrão 300/60 s. Token/interação preservam o padrão 30/60 s. Os contadores continuam por IP e por réplica, sem confiar em `client_id` ainda não autenticado.
- Rejeição usa o `Retry-After` fornecido pelo lease; fallback para a janela efetiva da operação. Mantém HTTP 429 e cabeçalhos sem cache.
- `BrowserRateLimitErrors` registrado somente com UI pública embutida. Navegação explícita em rotas interativas recebe HTML; APIs/fetch/XHR/preferência ambígua e hosts sem UI recebem JSON. Rotas reais de senha, 2FA e código de recuperação incluídas.
- `AuthorizationError.razor` e CSS existentes reutilizados, a partir da mudança `1b93ca3` de 09/09/2026. Preferência PT/EN vem de `Accept-Language`; variantes regionais normalizadas; fallback pt-BR. Texto explica a pausa e o tempo para tentar novamente. Sem reflexão de dados recebidos, URLs externas, scripts ou reenvio automático.
- Erros OAuth continuam com `temporarily_unavailable`; outros erros de rate limit usam `rate_limit_exceeded` em JSON, com descrição estável em inglês.

## Validação executada

- `rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --filter 'FullyQualifiedName~RateLimit|FullyQualifiedName~BrowserAuthorizationError' --logger 'trx;LogFileName=rate-limit-targeted.trx' -v quiet`: 82 testes aprovados na primeira rodada.
- `SUFFICIT_AUTH_PREVIEW_DIR=/tmp/identity-rate-browser rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --logger 'trx;LogFileName=identity-rate-full.trx' -v quiet`: 1.173 testes aprovados, sem erros. Inclui os formulários reais adicionados depois da primeira rodada e regressão do erro de autorização.
- Chrome headless via Playwright, usando HTML produzido pelos testes HTTP e CSS/fontes do repositório: pt-BR/en-US, 1440x900 e 390x844. Sem overflow horizontal, ação com 44 px, sem scripts/erros de página e inspeção visual desktop/mobile. Esta foi uma prévia local, não um teste do serviço em produção.
- `rtk dotnet restore Sufficit.Identity.sln --force-evaluate -p:SufficitUseLocalSui=false -v quiet`: restore concluído sem erros; locks em modo de pacotes. As diferenças dos locks são apenas NATS, da implementação anterior.
- Template JSON lido/validado em disco; `rtk git diff --check` sem problemas.

## Entrega e limites

Contrato/configuração: [Rate limiting](../networking/USAGE-RATE-LIMITING.md). Referências adicionadas ao índice e ONBOARD.

Evidência visual local: `/mnt/workspaces/sufficit/tmp/identity-rate-limit-pt-BR-mobile.png`, `/mnt/workspaces/sufficit/tmp/identity-rate-limit-pt-BR-desktop.png`, `/mnt/workspaces/sufficit/tmp/identity-rate-limit-en-US-mobile.png`, `/mnt/workspaces/sufficit/tmp/identity-rate-limit-en-US-desktop.png`. Resultados da prévia: `/tmp/identity-rate-browser/validation.json`.

Sem deploy ou commit nesta etapa. O ajuste depende de publicação para afetar os serviços. A proteção continua podendo rejeitar excesso dentro de cada operação; não há promessa de eliminar todos os 429. IPs compartilhados ainda dividem a mesma cota da operação na mesma réplica.
