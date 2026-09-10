# Gestão de audiências OAuth

A rota `/management/audiences` apresenta as audiências existentes e os scopes e
clientes associados. Ela integra o menu **OAuth & OIDC**, com a mesma autorização
da consulta de scopes. A implantação do código no servidor é necessária para
disponibilizar a rota no domínio público.

## Modelo e limites

- Audiência é o identificador do destinatário de um access token (`aud`). O
  inventário é derivado de `Resources` dos scopes OpenIddict; não existe outro
  cadastro ou tabela de audiências.
- Scope é a permissão solicitada pelo cliente. `chrome.phone`, por exemplo,
  solicita acesso à API com audiência `SufficitEndpointsIntrospection`.
- Entitlements são atributos de autorização, não substitutos de uma audiência.
  A tela não adiciona recursos a scopes de claims/protocolo ou reservados.
- Clientes exibidos são os que têm permissão para solicitar os scopes vinculados;
  isso não comprova emissão recente de tokens nem autorização de negócio na API.
- Recursos são comparados com distinção entre maiúsculas e minúsculas.
- A configuração de validação da API não é alterada por esta tela. Mudanças de
  vínculo afetam novas emissões; não revogam automaticamente tokens existentes.

## Operações

**Consultar:** pesquise por audiência, scope ou identificador de cliente. Expanda
a contagem de clientes para consultar os identificadores; abra um scope para
examinar sua definição. Scopes sem recursos permanecem disponíveis como destinos
no formulário, mas não produzem linhas de audiência.

**Registrar ou vincular:** clique em “Vincular audiência”, informe o identificador
e selecione um scope manual de API. Salvar acrescenta apenas esse recurso e
preserva nome, descrição e demais recursos do scope. Uma audiência só existe no
inventário enquanto houver pelo menos um vínculo. Para adicionar um scope novo,
use o módulo Scopes.

**Remover:** use “Remover vínculo” na linha do scope. A confirmação identifica
exatamente o scope e a audiência. A operação não exclui scope, cliente, grants ou
tokens. Remover o último vínculo elimina a audiência do inventário derivado.

**Manifestos:** scopes declarativos aparecem com o marcador “Manifesto”, sem
ações de escrita. A alteração deve ser feita no manifesto do proprietário e
aplicada pelo provisionamento. Não existe renomeação global automática.

## Segurança, concorrência e auditoria

UI e REST utilizam o mesmo `IScopeManagementService`. Consultas exigem
`identity.scopes.read`; escritas exigem `identity.scopes.update`, além das
políticas de MFA e acesso a objetos do Management. Esconder botões não substitui
a validação da operação no serviço.

- `GET /api/audiences`: inventário com audiências, scopes e IDs de clientes.
- `PUT /api/audiences/scopes/{scopeId}`: altera um vínculo; corpo
  `{ "audience": "orders-api", "assigned": true, "expectedResources": [] }`.
- `expectedResources` deve reproduzir os recursos do scope lido. Um snapshot
  obsoleto resulta em HTTP 409; o formulário mantém os dados e oferece atualização
  para revisão. A atualização de entidade mantém a concorrência do OpenIddict.
- Escritas usam a transação/auditoria canônica de atualização de scopes
  (`scope_updated`). Leituras não criam linhas de auditoria.
- Recursos inválidos retornam 400, scopes inexistentes 404 e alterações em scopes
  declarativos 409. DTOs não contêm tokens, segredos ou credenciais de clientes.

## Validação local

```sh
dotnet test src/tests/Sufficit.Identity.Tests.csproj -p:SufficitUseLocalSui=false
```

O teste `Audience_browser_host_serves_authenticated_screen` sobe um servidor
Kestrel somente em loopback com cookies e dados de teste. Para executar também
as interações Playwright e capturar desktop/celular, defina
`IDENTITY_AUDIENCE_BROWSER_SCRIPT` com o caminho absoluto de
`scripts/check-audiences-browser.mjs` e `IDENTITY_PLAYWRIGHT_PACKAGE` com o caminho
de um `package.json` que resolva o pacote Playwright instalado. O script rejeita
hosts que não sejam `127.0.0.1`; não deve ser usado em produção.

O menu Configurações usa correspondência exata. A rota
`/management/settings/trusted-proxies` destaca somente “Proxies confiáveis”.
