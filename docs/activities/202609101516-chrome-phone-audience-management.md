# Chrome Phone e gestão de audiências

## Entrega e estado inicial

Implementados o nome de scope solicitado pelo usuário (`chrome.phone`), a tela
`/management/audiences` e a correção de seleção simultânea de Configurações e
Proxies confiáveis. A implementação do Identity está concluída localmente;
**a nova tela e a correção de menu ainda não foram publicadas em produção**.

O repositório Identity estava limpo. Alterações anteriores da extensão e do
Endpoints foram preservadas. Nenhum commit ou push foi executado nesta etapa.
Não houve alteração de validação de tokens, migração de banco ou reinício do
Identity. A alteração produtiva foi limitada ao registro/permissão do scope.

## Escopo Chrome Phone

- Extensão 2.17.166 solicita `openid profile email offline_access chrome.phone`.
- Manifestos da extensão e do Endpoints registram o nome escolhido pelo usuário;
  audiência da API continua `SufficitEndpointsIntrospection`.
- `endpoints.phone` foi mantido como compatibilidade para versões anteriores,
  mas não é solicitado pelo OAuth atualizado. Não foi reintroduzido directives.
- SQL administrativo foi ensaiado com rollback, aplicado (1 scope/1 permissão)
  e repetido sem mutações (0/0). PKCE, consentimento explícito e callbacks foram
  preservados. Sem impressão de credenciais.
- Probes HTTPS individuais nas três instâncias aceitaram `chrome.phone` e
  retornaram `login_required` sem cookies. Isso verifica registro/permissão,
  **não comprova login autenticado nem resposta 200 da API de configuração**.
- Pacote local: `sufficit-chrome-extension-phone/dist/extension-2.17.166-UZWXs5`.
  Sem publicação na Web Store; novo login com a extensão atualizada ainda é a
  verificação end-to-end da sessão do usuário.

## Gestão de audiências

- Inventário derivado dos recursos de scopes, sem novo registro paralelo.
- Contratos compartilhados, serviço canônico, REST e datasource Blazor.
- Pesquisa por audiência/scope/cliente, vínculos de manifesto somente leitura,
  adição de recurso a scope manual e confirmação antes da remoção de um vínculo.
- Capabilities de leitura/atualização, políticas de MFA/acesso a objetos,
  validação, snapshot esperado, concorrência da entidade e auditoria canônica.
- Interface usa componentes SUI existentes e layout responsivo. Estados de
  carregamento, falha, vazio e sucesso separados; conflitos preservam o input;
  retorno do foco do teclado após fechamento/conclusão.
- Settings usa `NavLinkMatch.All`; a rota de Trusted Proxies destaca apenas seu
  próprio item. Demais links conservam correspondência de prefixo para detalhes.

## Validação

- Extensão: 14 testes focados de OAuth/manifesto, ESLint e build 2.17.166 aprovados.
- Identity: suíte completa com **1194 aprovados, 1 ignorado**, de 1195 testes.
  Casos novos cobrem inventário, escrita/remoção, snapshot obsoleto, escopo de
  claims, manifesto, auditoria, autorização de serviço/HTTP e rotas/menu.
- Playwright em Kestrel isolado e dados em memória: adicionar, remover, cancelar,
  pesquisar, resultado vazio, conflito com input preservado, recarregar para
  revisão, foco real via `document.activeElement`, consulta indisponível e menu.
  Capturas desktop 1440 e celular 390; sem overflow horizontal. Não usa cookies
  nem dados produtivos.
- Detector visual executado uma vez: `[]`. Revisor independente pediu rodapé
  verdadeiro em falha e restauração de foco; ambos corrigidos e classificados
  como resolvidos, disposição **ship**, restrita aos dois apontamentos.
- `git diff --check` aprovado nos três repositórios; script de navegador passa
  `node --check`. Documentação segue contratos de nomes e links do projeto.
- Build/testes usam `-p:SufficitUseLocalSui=false`. O primeiro teste sem restore
  misturou pacote e projeto SUI local e falhou CS1704; restore consistente em modo
  pacote resolveu. Nenhuma dependência nova foi adicionada.
- Publish Release concluído em `/tmp/identity-audiences-release.sRn3su`, com DLLs
  e assets estáticos verificados. SHA256 Server.dll:
  `a1cfd92e4b0e0a6ea1810c43b0400f6ee322013692cb0d64637d0d36b0fec313`;
  UI.Management.dll:
  `45a5c17b7b076a2e69d15e48fc13b4bea4a1ca3a68c3609e504523c2e45df587`.

## Publicação e referências

O empacotador oficial exige Git limpo. Os auxiliares de ativação assumem symlinks,
enquanto os relatos dos últimos deploys registram diretórios comuns com staging
e backup. Portanto este trabalho não substituiu o serviço: commit/release e
ativação coordenada precisam de autorização e do procedimento compatível com o
estado real. O publish local usa SUI publicado; o último deploy usou SUI local,
uma diferença que também deve ser reconciliada antes de ativar o artefato.

- [Uso, API e limites](../management/USAGE-AUDIENCES.md)
- [Contrato visual da superfície](../design/DESIGN-AUDIENCES.md)
- [Último procedimento de produção](202609101258-deploy-rate-limit-browser-errors.md)

Plano temporário consolidado neste relatório após conclusão da implementação e
validação local. A skill software-development orientou os checkpoints e a
rastreabilidade; impeccable/sufficit-frontend preservaram o sistema visual e
exigiram a revisão independente e os estados acessíveis.
