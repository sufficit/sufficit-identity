# PLAN-MANAGEMENT-APPLICATIONS — gerenciamento completo de aplicações OAuth/OIDC

> **Status:** In progress — pendências de gerenciamento de aplicações · **Owner:** Sufficit · **Created:** 2026-08-07 · **Updated:** 2026-08-08
> **Primary surface:** `/management/clients` · **Provider:** OpenIddict 7.6
> **Legacy reference:** `sufficit-identity-legacy` / Skoruba Duende Admin

## 1. Objetivo

Completar o gerenciamento de aplicações OAuth/OIDC no Sufficit Identity sem
transformar a console em uma cópia do Skoruba e sem incorporar papéis,
diretivas ou regras empresariais da Sufficit ao provedor genérico.

O operador deve conseguir localizar, criar, consultar, editar, clonar,
desabilitar com segurança e administrar credenciais de uma aplicação pelos
mesmos casos de uso consumidos pela Management API. Toda mutação deve aplicar
validação centralizada, autorização por capability, MFA quando exigido,
auditoria e proteção de segredos.

A criação e a edição devem ser experiências guiadas, mobile-first e retomáveis,
não formulários técnicos de texto livre. O produto traduz a intenção do
operador em configuração OpenIddict segura, explica cada decisão e mantém o
progresso sem expor segredo ou configuração sensível na URL.

## 2. Diagnóstico confirmado

### 2.1 Existem duas interfaces diferentes

| Rota | Responsabilidade | Pode administrar aplicações? |
| --- | --- | --- |
| `/manage` | Autoatendimento da conta autenticada: perfil, MFA, passkeys, sessões e aplicações conectadas | Não; mostra somente os próprios acessos |
| `/management` | Console administrativa do provedor | Sim, conforme capabilities do operador |
| `/management/clients` | Lista de clientes/aplicações OAuth/OIDC | Sim, mas hoje com contrato incompleto |

Essa separação é intencional. A ausência de aplicações em `/manage` não é um
defeito; a baixa descoberta da console `/management` e suas capabilities deve
ser tratada na navegação/documentação do deployment.

### 2.2 O que já existe no Identity atual

- listagem e pesquisa local de clientes;
- detalhe somente leitura;
- criação de cliente público ou confidencial;
- configuração inicial de consentimento, PAR, grant types, scopes, redirects e
  logout federado;
- exclusão confirmada e auditada;
- CRUD completo de claims personalizadas por usuário;
- CRUD completo de scopes OpenIddict, incluindo resources/audiences e clientes
  vinculados;
- sessões e autorizações filtráveis por cliente;
- provisionamento declarativo capaz de criar e atualizar clientes gerenciados
  por manifesto;
- capabilities `identity.clients.read`, `identity.clients.create`,
  `identity.clients.update` e `identity.clients.delete`.

### 2.3 Lacuna real

O contrato `IClientManagementService` agora oferece `List`, `Get`, `Create`,
`Update` e `Delete`. Permanecem como próximas lacunas:

- paginação/pesquisa no servidor;
- habilitação/desabilitação operacional;
- rotação ou remoção de client secret;
- metadados seguros de credencial;
- clonagem;
- indicação de cliente gerenciado por manifesto (agora disponível no detalhe e
  bloqueia edição manual);
- configuração tipada de tempos de vida por aplicação;
- metadados públicos da aplicação, como descrição, URL e logotipo;
- administração segura de propriedades/claims específicas do cliente.

O resultado é uma interface que aparenta administrar aplicações, mas só cobre
o início e o fim do ciclo de vida.

### 2.4 Limitações confirmadas da criação atual

`ClientCreate.razor` concentra toda a configuração em uma única página. Embora
o backend valide parte do contrato, a experiência atual dificulta o uso:

- tipo público/confidencial é inferido pela presença de `ClientSecret`, em vez
  de nascer da intenção e do perfil da aplicação;
- grants são checkboxes técnicos sem validação visível das combinações;
- scopes são digitados em um campo livre, sem catálogo, descrição ou indicação
  de resource/audience;
- redirects e post-logout redirects são áreas de texto, uma URI por linha;
- não há validação contextual antes do envio nem associação consistente entre
  erro do serviço, campo e orientação de correção;
- consentimento, PAR, PKCE e logout são expostos como termos de protocolo, mas
  não como consequências compreensíveis;
- não existe rascunho, retomada, URL por etapa, revisão da configuração resolvida
  ou modo assistido por perfil;
- apesar de o CSS empilhar o formulário abaixo de 768 px, a interação continua
  sendo um formulário desktop longo comprimido no celular.

O backend já rejeita client ID inválido, URIs relativas ou com fragmento, HTTP
fora de loopback, origem incompatível de front-channel logout, grants
`password`/`implicit` e scopes administrativos reservados. Essas regras precisam
ser extraídas para um validator compartilhado e apresentadas antes da submissão
final, com mensagens localizadas e acionáveis.

### 2.5 Por que o módulo pode não aparecer para um operador

A navegação da Management UI é filtrada pelas capabilities efetivas. Na
configuração versionada em `deploy/local/appsettings.json`, a role
`administrator` está em `FullAdministratorRoles`, enquanto `manager` recebe
somente:

- `identity.users.read`;
- `identity.claims.read`;
- `identity.claims.create`;
- `identity.claims.delete`.

Portanto, um operador autenticado apenas como `manager` não verá Aplicações,
porque não possui `identity.clients.read`, e poderá criar/excluir claims sem
editá-las, porque não possui `identity.claims.update`. Esse comportamento é
coerente com o isolamento entre roles empresariais e administração do provedor,
mas a configuração do deployment deve usar uma role administrativa dedicada ou
um mapeamento granular explícito. Não se deve transformar toda role de negócio
`manager` em administradora de aplicações por conveniência.

## 3. Comparação com o legado

### 3.1 Matriz funcional

| Área | Identity atual | Skoruba legado | Direção para o Identity novo |
| --- | --- | --- | --- |
| Lista | carrega todos e filtra no circuito | pesquisa e paginação no servidor | paginação, busca e filtros no serviço de aplicação |
| Criação | formulário único, técnico e sem retomada | wizard por tipo com revisão | configurador guiado, rascunho persistente, URL por etapa e revisão final |
| Edição | ausente | cinco grupos principais e várias subabas | implementar edição tipada por seções |
| Clone | ausente | copia configuração e exige nova identidade/credencial | clonar somente configuração não secreta |
| Ativação | ausente | `Enabled` | só oferecer após existir bloqueio efetivo no runtime |
| Redirect/logout | cria e consulta | CRUD completo | editar, validar e comparar mudanças |
| CORS | ausente | permitido por cliente | não copiar até existir consumidor/enforcement no runtime OpenIddict |
| Scopes/grants | texto na criação, leitura técnica no detalhe | seletores estruturados | seletores a partir dos contratos de scopes e features habilitadas |
| Segredos | um valor na criação; nunca mais gerenciado | múltiplos segredos com descrição e expiração | rotação atômica/secret reference; nunca listar ou recuperar segredo |
| Consentimento | tipo básico | consentimento, lembrança, duração e metadados | mapear somente opções suportadas e realmente aplicadas |
| Token lifetime | global, com leitura parcial por aplicação no device flow | vários tempos por cliente | expor settings OpenIddict por aplicação com limites seguros |
| PKCE/PAR | defaults e requirements parciais | configuração por cliente | editar requirements suportados, sem enfraquecer defaults globais |
| Device flow | suportado pelo runtime/provisionamento | configurável | oferecer grant e endpoints quando habilitados pelo runtime |
| CIBA, DPoP, JAR/FAPI | recursos do runtime majoritariamente globais/customizados | controles por cliente no Duende | não criar toggles até existir enforcement por aplicação |
| Claims do cliente | ausente | CRUD de claims do cliente | contrato separado e allowlist; não confundir com claims do usuário |
| Propriedades | internas ao OpenIddict/manifesto | CRUD arbitrário | preferir metadados tipados; propriedades brutas somente em modo avançado protegido |
| Usuário/claims | CRUD de claims já completo | claims, roles e role claims | manter claims; roles empresariais continuam fora do provedor genérico |
| Recursos | scopes OpenIddict contêm resources/audiences | Identity Resources, API Resources e API Scopes separados | manter o modelo OpenIddict; não recriar entidades Duende |

### 3.2 O que não deve ser copiado

- `IdentityResource` e `ApiResource` como entidades independentes: no modelo
  atual, scopes e seus `resources`/audiences representam essa relação.
- `AccessTokenType` do Duende sem equivalente consumido pelo runtime.
- `AllowedCorsOrigins` apenas como dado decorativo. Se houver necessidade, a
  política CORS precisa ser aplicada de verdade no pipeline.
- papéis, diretivas, tenants, clientes comerciais ou departamentos da Sufficit.
- campos DPoP, CIBA, JAR ou FAPI que não alterem uma decisão real do protocolo.
- propriedades arbitrárias que possam substituir configurações reservadas do
  OpenIddict ou do provisionamento.

## 4. Limites de domínio

### 4.1 Claims do usuário

Já possuem pesquisa, criação, edição e exclusão em:

- `/management/users/{id}` → ação **Claims da conta**;
- `/management/claims?user={id}`;
- `/management/claims/new?user={id}`;
- `/management/claims/edit?user={id}&claim={claimId}`.

Claims reservadas, incluindo `sub`, `role`, `permission`, `scope` e claims de
protocolo, permanecem protegidas. Cada mutação atualiza o security stamp, revoga
tokens e não copia o valor para a auditoria.

Melhoria prevista: tornar o acesso às claims mais descobrível no detalhe do
usuário, sem criar um catálogo de roles empresariais.

### 4.2 Claims da aplicação

São diferentes de claims do usuário. Caso sejam implementadas, representam
atributos emitidos para uma identidade de cliente, principalmente em
`client_credentials`. Elas precisam de:

- contrato próprio;
- namespaces/tipos permitidos;
- bloqueio de `iss`, `sub`, `aud`, `scope`, `permission`, `role`, `cnf` e demais
  claims de segurança;
- política explícita de destinos do token;
- testes demonstrando que não ampliam scopes nem capabilities;
- auditoria sem valor sensível.

Não devem reutilizar diretamente o CRUD de claims de usuário.

### 4.3 Clientes gerenciados por manifesto

O provisionador já atualiza aplicações declarativas. A edição manual não pode
criar duas fontes de verdade. O detalhe precisa projetar `IsManifestManaged` e:

- manter esses clientes somente leitura na edição comum;
- apontar o operador para `/management/provisioning`;
- permitir rotação somente pelo `SecretReference` do manifesto;
- registrar claramente quais campos são declarativos.

## 5. Arquitetura-alvo

```text
Management UI ─┐
               ├──> IClientManagementService ──> OpenIddict manager/store
Management API ┘             │
                             ├──> IClientDefinitionValidator
                             ├──> IManagementScopeGrantPolicy
                             ├──> IClientConfigurationDraftService
                             ├──> IClientSecretResolver / Vault
                             └──> management audit + metrics
```

Regras:

1. UI e API usam o mesmo comando e o mesmo serviço.
2. O serviço carrega o descriptor atual, aplica somente campos autorizados,
   valida o resultado completo e persiste em transação.
3. A UI nunca recebe hash, secret, reference token ou payload.
4. Configuração global de segurança é o piso; uma aplicação não pode
   enfraquecê-la.
5. Clientes de manifesto não são alterados pelo CRUD manual.
6. Mudanças incompatíveis exibem impacto e exigem confirmação.
7. O rascunho persiste intenção e configuração não sensível; OpenIddict só é
   alterado na confirmação final.
8. A URL identifica a etapa e o rascunho, mas nunca contém segredo, token,
   claim, lista extensa de URI ou outro dado sensível.

## 6. Contratos propostos

### 6.1 Capabilities

Adicionar granularmente:

- `identity.clients.update`;
- `identity.clients.clone`;
- `identity.clients.disable`;
- `identity.clients.rotate-secret`;
- `identity.clients.manage-claims` — somente quando o contrato existir;
- `identity.clients.manage-properties` — somente para propriedades liberadas.

`identity.clients.read` continua sendo a capability mínima para a rota e para o
menu. Capability de leitura nunca autoriza mutação.

### 6.2 Consulta

```csharp
public sealed record ManagementClientSearch(
    string? Search = null,
    string? Type = null,
    string? GrantType = null,
    string? Scope = null,
    int Page = 1,
    int PageSize = 25);

public sealed record ManagementClientPage(
    IReadOnlyList<ManagementClientSummary> Items,
    int Page,
    int PageSize,
    int TotalCount);
```

`ManagementClientSummary` deve projetar somente estado seguro: ID, client ID,
nome, tipo, origem de gerenciamento e um estado operacional real quando esse
estado existir.

### 6.3 Atualização

Criar `UpdateManagementClientCommand` com campos tipados, sem aceitar um
`OpenIddictApplicationDescriptor` cru. Primeira entrega:

- `DisplayName`;
- `ConsentType`;
- grant types e response types suportados;
- scopes;
- redirect e post-logout redirect URIs;
- front/back-channel logout e seus flags;
- PKCE/PAR requirements;
- access/identity/refresh token lifetimes por aplicação, quando suportados.

O `ClientId` permanece imutável. Alteração de tipo público/confidencial ocorre
somente por operação explícita de credencial, não como efeito colateral de um
campo de texto vazio.

### 6.4 Credencial

Priorizar o contrato já previsto em `PLAN-GLM-5-2-REMAINING.md`:

```csharp
public sealed record RotateManagementClientSecretCommand(
    string ClientId,
    string SecretReference,
    DateTimeOffset? ActivateAt = null);
```

- resolver o valor por `IClientSecretResolver`/Vault;
- nunca aceitar o segredo em list/detail;
- não registrar valor ou hash na auditoria;
- rotação deve invalidar o segredo anterior de forma explícita;
- sobreposição de dois segredos exige modelo persistente e validação de
  autenticação próprios; não simular suporte que o store atual não possui;
- para operação humana sem secret store, um modo “mostrar uma vez” só entra
  após desenho específico de armazenamento/entrega efêmera e confirmação de
  risco.

### 6.5 Clone

`CloneManagementClientCommand` recebe cliente de origem, novo `ClientId`, novo
nome e referência de segredo opcional. Copia apenas configuração permitida;
credenciais, autorizações, sessões, auditoria, métricas e propriedades internas
do manifesto nunca são copiadas.

### 6.6 Rascunho de configuração

Criar um contrato próprio, anterior à aplicação OpenIddict:

```csharp
public sealed record ManagementClientDraft(
    Guid Id,
    string OwnerSubject,
    string Profile,
    string CurrentStep,
    ManagementClientDraftValues Values,
    ClientDraftValidation Validation,
    string Version,
    DateTimeOffset UpdatedAt,
    DateTimeOffset ExpiresAt);
```

Operações mínimas:

- criar a partir de um perfil seguro;
- consultar somente pelo operador autorizado;
- salvar parcialmente com controle de concorrência;
- validar um campo, uma etapa ou o rascunho completo;
- listar rascunhos do operador para **Continuar configuração**;
- abandonar e excluir explicitamente;
- finalizar de forma idempotente, criando a aplicação uma única vez.

O rascunho é persistido no servidor e tem expiração configurável. Não contém
segredo em claro. Uma credencial usa `SecretReference` ou é gerada somente na
finalização por um fluxo de exibição única desenhado especificamente para isso.
Trocar de etapa não grava uma aplicação OpenIddict incompleta.

Os valores não indexáveis do rascunho são armazenados como payload protegido
com o key ring compartilhado do ASP.NET Core Data Protection, para que a
retomada funcione entre múltiplas instâncias sem deixar URIs e configuração em
texto aberto no banco. Somente ID, proprietário, perfil, etapa, status, versão e
datas ficam disponíveis como metadados operacionais. Expiração e abandono
removem o payload por rotina idempotente.

### 6.7 Resultado de validação

O validator compartilhado devolve informação consumível tanto por API quanto
por UI:

```csharp
public sealed record ClientValidationIssue(
    string Code,
    string Step,
    string Field,
    string Severity,
    string Message,
    string? Remediation = null);
```

Os códigos são estáveis e as mensagens são localizadas na borda de
apresentação. O serviço continua sendo a autoridade: validação antecipada no
navegador melhora a resposta, mas nunca substitui a validação final no servidor.

## 7. Estrutura da interface

Modo da superfície: **Operate**. Preservar `DESIGN-MANAGEMENT-UI.md`.

A qualidade “gamificada” vem de progresso compreensível, pequenas conclusões e
feedback de prontidão — não de pontos, confete ou linguagem infantil. É uma
configuração de segurança: deve ser acolhedora e inteligente sem perder
seriedade operacional.

### 7.1 Lista `/management/clients`

- renomear a apresentação para **Aplicações** e manter “cliente OAuth/OIDC” no
  texto técnico;
- pesquisa paginada no servidor;
- filtros por tipo, grant e scope;
- sincronizar `q`, `type`, `grant`, `scope`, `origin`, `status`, `page` e
  `pageSize` na query string, omitindo valores padrão;
- aplicar filtros com histórico navegável, de modo que F5, Voltar, Avançar e
  compartilhamento da URL preservem exatamente a visão;
- coluna de origem: manual ou manifesto;
- ação primária **Nova aplicação**;
- bloco **Continuar configuração** para rascunhos ainda válidos;
- estado de capability ausente distinto de coleção vazia;
- no mobile, transformar cada linha em registro rotulado, sem tabela horizontal.

### 7.2 Entrada do configurador

`/management/clients/new` começa pela pergunta **Como esta aplicação será
usada?**, com perfis derivados das features realmente habilitadas no servidor:

1. **Aplicação web / BFF** — authorization code, PKCE, redirects e, quando
   necessário, refresh token e credencial.
2. **SPA pública** — authorization code com PKCE, sem segredo no navegador.
3. **Aplicativo móvel ou desktop** — cliente público e redirects apropriados ao
   tipo de aplicação; custom schemes só entram após política e testes conforme
   RFC 8252, mantendo loopback como opção suportada.
4. **Serviço para serviço** — client credentials, credencial e scopes de API;
   sem scopes de identidade do usuário.
5. **Dispositivo ou CLI** — device authorization e renovação somente quando o
   runtime estiver habilitado para esse fluxo.
6. **Configuração avançada** — começa com defaults seguros e mantém todas as
   restrições do validator.

Cada perfil mostra, antes da seleção: onde é usado, o que será habilitado, quais
dados serão necessários e quais riscos evita. A seleção cria o rascunho e
preenche defaults, mas nenhuma escolha oculta fica irreversível.

### 7.3 Rotas e retomada por etapa

Cada etapa tem uma rota real dentro do PathBase da Management UI:

```text
/management/clients/drafts/{draftId}/identity
/management/clients/drafts/{draftId}/protocol
/management/clients/drafts/{draftId}/permissions
/management/clients/drafts/{draftId}/uris
/management/clients/drafts/{draftId}/credentials
/management/clients/drafts/{draftId}/review
```

- a rota é a fonte de verdade da etapa atual;
- F5 restaura o rascunho e a mesma etapa;
- Voltar/Avançar do navegador navegam entre etapas sem perder mudanças salvas;
- **Salvar e sair** retorna à lista, onde o rascunho pode ser retomado;
- acessar uma etapa fora de ordem redireciona para a primeira pendência e
  explica o motivo;
- link de rascunho exige autenticação e autorização do proprietário/operador;
- a URL contém apenas `draftId`, etapa e estado visual não sensível;
- segredo, token, claim, URIs e scopes permanecem no rascunho protegido, nunca
  na URL ou no histórico do navegador.

O autosave ocorre após mudanças válidas, com debounce e indicador textual
**Salvo agora**, **Salvando…** ou **Não foi possível salvar**. Conflitos usam a
versão do rascunho e nunca sobrescrevem silenciosamente outra sessão.

### 7.4 Sequência do configurador

1. **Identidade** — nome, sugestão editável de client ID, descrição e perfil.
2. **Protocolo** — intenção do fluxo, tipo público/confidencial, consentimento,
   PKCE e PAR. Grants e response types são derivados e explicados.
3. **Permissões** — seletor pesquisável de scopes existentes, agrupado em
   identidade e APIs, com descrição, resource/audience e indicação de risco.
4. **URIs** — campos repetíveis para redirect, post-logout e logout de canal,
   cada URI validada isoladamente; colar múltiplas linhas continua disponível.
5. **Credenciais** — somente quando o perfil exigir, usando referência segura ou
   fluxo explícito de geração/exibição única.
6. **Revisão** — resumo em linguagem humana do que a aplicação poderá fazer,
   configuração técnica resolvida, pendências, avisos e confirmação final.

O cabeçalho mostra etapa atual, progresso e estado do rascunho. Etapas concluídas
recebem check e continuam acessíveis. Etapas com erro recebem rótulo textual,
nunca apenas cor. A etapa atual contém uma tarefa principal e evita painéis
laterais concorrentes no celular.

### 7.5 Controles inteligentes

- substituir campos de scopes e grants por seletores baseados nos scopes padrão
  reconhecidos pelo protocolo e no catálogo persistido do servidor;
  identificadores técnicos continuam visíveis como informação;
- usar campos repetíveis para URIs, com adicionar, remover, colar lista e erro
  junto da URI exata;
- explicar consentimento como comportamento para o usuário, não apenas os
  valores `explicit`, `implicit`, `external` e `systematic`;
- derivar endpoint permissions e response types a partir do fluxo, exibindo-os
  na revisão sem pedir que o operador os memorize;
- oferecer defaults seguros e uma ação **Por que isso é necessário?** para
  PKCE, PAR, segredo, consentimento e logout;
- permitir trocar de perfil mostrando previamente quais valores serão mantidos,
  removidos ou precisam ser revistos;
- nunca usar textarea genérico quando o domínio possuir estrutura validável.

### 7.6 Validação e orientação

Validar progressivamente e novamente ao avançar/finalizar:

- client ID obrigatório, tamanho, formato recomendado e unicidade;
- perfil, tipo do cliente, grants, response types, endpoints e credencial;
- `offline_access` dependente de refresh token;
- scopes de identidade incompatíveis com um fluxo puramente
  `client_credentials`;
- scopes padrão reconhecidos ou registrados, permitidos pela política e não
  reservados;
- URI absoluta, ausência de fragmento, HTTPS fora de loopback e duplicidade;
- presença de redirect para fluxos interativos;
- mesma origem do front-channel logout quando a regra se aplicar;
- segredo ausente em cliente confidencial e segredo indevido em cliente
  público;
- requisitos globais de PKCE/PAR que não podem ser enfraquecidos por cliente.

Cada erro informa: o que aconteceu, por que importa e como corrigir. O resumo de
etapas leva o foco ao primeiro erro; o topo da página não recebe uma mensagem
genérica desconectada dos campos. Avisos não bloqueantes são separados de erros.

### 7.7 Revisão e conclusão

A revisão apresenta três blocos:

- **O que esta aplicação poderá fazer**;
- **Como usuários e serviços irão autenticar**;
- **O que ainda exige atenção**.

Uma expansão **Ver configuração técnica** mostra client type, grants, response
types, endpoint permissions, scopes, requirements e URIs derivados. O botão
**Criar aplicação** só habilita com o rascunho pronto. A finalização é
idempotente e, em sucesso, navega para o detalhe da aplicação com confirmação e
próximos passos, sem recriar ao atualizar a página.

### 7.8 Detalhe `/management/clients/{id}`

Usar navegação interna responsiva, sem reproduzir a quantidade de abas aninhadas
do legado:

1. **Visão geral** — identidade, tipo, consentimento, origem e uso recente.
2. **Protocolos e permissões** — grants, endpoints, response types, scopes,
   PKCE/PAR e features efetivamente suportadas.
3. **URIs** — redirects e logout federado.
4. **Credenciais** — estado seguro, rotação e orientação para Vault.
5. **Metadados avançados** — lifetimes e propriedades tipadas.
6. **Atividade** — sessões, autorizações, auditoria e métricas filtradas.

Em telas pequenas, as seções viram uma lista/accordion sem perder URL,
hierarquia, foco ou estado. A ação destrutiva permanece separada no fim.

### 7.9 Edição

- edição inicia em modo leitura e exige ação explícita **Editar**;
- reutiliza as mesmas etapas, controles e validações do configurador;
- cada seção editável possui URL própria e preserva retorno ao detalhe;
- alterações ficam visíveis em um resumo antes de salvar;
- mudança que remove redirect, grant ou scope informa impacto;
- campos disponíveis vêm da capacidade real do runtime, não de uma lista
  duplicada no frontend;
- salvar mantém o operador na aplicação e confirma o que mudou;
- conflito de concorrência não sobrescreve silenciosamente uma edição mais
  recente.

### 7.10 Mobile-first, acessibilidade e localização

- desenhar primeiro para 320–430 px e expandir progressivamente;
- uma coluna principal, sem tabela ou formulário horizontal no configurador;
- ações **Voltar** e **Continuar** ficam em uma barra inferior sticky que
  respeita safe area e teclado virtual;
- alvos de toque têm pelo menos 44 × 44 px;
- progresso compacto mostra “Etapa 2 de 6” no celular e navegação completa
  quando houver largura;
- nenhum conteúdo essencial depende de hover, tooltip ou gesto oculto;
- foco segue título, campo inválido e confirmação; erros usam `aria-describedby`
  e resumo com links;
- mudanças assíncronas e autosave usam regiões `aria-live` sem interromper a
  digitação;
- nomes amigáveis são localizados; valores OAuth/OIDC permanecem invariáveis e
  monoespaçados;
- textos longos, URLs e identificadores quebram com segurança sem overflow;
- animação é curta e funcional e respeita `prefers-reduced-motion`.

### 7.11 Descoberta

- documentar claramente `/management` como console administrativa;
- exibir link **Administração** no shell público somente para operadores que
  possuam alguma capability;
- manter `/manage` como autoatendimento e nunca misturar suas ações;
- quando `clients.read` não estiver presente, mostrar o motivo em Settings/Home
  sem renderizar um link que terminará em `403`.

## 8. Fases de implementação

### Fase 0 — contrato e segurança compartilhados

- [ ] concluir `IClientDefinitionValidator` compartilhado entre CRUD e
  provisionamento, conforme `PLAN-GLM-5-2-REMAINING.md` P0.2;
- [x] devolver issues estáveis por etapa/campo e manter localização na UI;
- [ ] implementar `IManagementScopeGrantPolicy` e shadow decisions;
- [ ] criar catálogo de perfis a partir das features habilitadas no runtime;
- [x] criar entidade, migration e `IClientConfigurationDraftService`, com
  ownership, expiração, versionamento e limpeza;
- [x] garantir por teste que rascunho, URL, log e auditoria não recebem segredo;
- [ ] adicionar `ClientsUpdate` e separar policies de leitura/mutação;
- [ ] projetar `IsManifestManaged` no detalhe;
- [x] adicionar ETag/version token ou equivalente para concorrência;
- [ ] caracterizar os clientes existentes antes de alterar contratos.

### Fase 1 — configurador guiado de criação

- [x] implementar `/clients/new` com seleção de perfil explicada;
- [x] implementar rotas por `draftId` e etapa;
- [x] autosave, **Salvar e sair**, retomada, abandono e expiração;
- [x] controles estruturados de grants, scopes e URIs;
- [x] validação de campo, etapa e configuração completa;
- [x] revisão humana e resumo técnico da configuração derivada;
- [x] finalização idempotente usando o mesmo `CreateAsync` da API;
- [x] sincronizar filtros da lista com a URL;
- [ ] entregar e testar primeiro em 320–430 px, depois tablet e desktop;
- [x] remover o formulário único somente após equivalência e migração de links.

### Fase 2 — edição essencial ponta a ponta

- [ ] `UpdateManagementClientCommand` e serviço;
- [ ] `PUT /api/clients/{clientId}` com resposta de detalhe;
- [ ] adapter da Management UI;
- [ ] reutilizar etapas e componentes do configurador para nome,
  consentimento, grants, scopes, PKCE/PAR e URIs;
- [ ] validação de combinação de tipo/grant/endpoint/redirect;
- [ ] auditoria com diff de nomes de campos, sem valores sensíveis;
- [ ] bloqueio de edição para manifesto;
- [ ] resumo de impacto e detalhe responsivo.

### Fase 3 — credenciais e clonagem

- [ ] integrar `SecretReference` e Vault;
- [ ] rotação explícita com capability própria;
- [ ] exibir apenas “credencial configurada”, origem e data segura quando
  disponível;
- [ ] clonagem sem segredos ou estado operacional;
- [ ] confirmar impacto e revogar autorizações/tokens somente quando a política
  da operação exigir;
- [ ] documentar rollback e recuperação.

### Fase 4 — operação e escala

- [ ] pesquisa/paginação/filtros no banco;
- [ ] estado de desabilitação com enforcement no authorize/token/PAR/device;
- [ ] métricas por aplicação ligadas ao módulo já existente;
- [ ] timeline de auditoria filtrada pelo client ID;
- [ ] ações de revogação de sessões/autorizações no contexto da aplicação;
- [ ] teste de volume com milhares de clientes.

### Fase 5 — avançado, somente com enforcement real

- [ ] lifetimes por aplicação;
- [ ] metadados públicos tipados (`description`, `client_uri`, `logo_uri`);
- [ ] claims de aplicação com allowlist e destinos;
- [ ] propriedades avançadas com namespace e chaves reservadas;
- [ ] configuração per-client de DPoP/JAR/CIBA/FAPI somente onde o runtime
  consultar e aplicar a decisão;
- [ ] novos perfis somente quando possuírem validator, explicação e testes de
  protocolo correspondentes.

## 9. Segurança

- Validar URI absoluta, fragmento, HTTPS e loopback como no contrato atual.
- Revalidar o descriptor completo em toda atualização; não validar somente o
  campo alterado.
- Bloquear scopes administrativos reservados e scopes fora da autoridade do
  operador.
- Não permitir remoção silenciosa de PKCE/PAR quando exigidos globalmente.
- Exigir MFA/step-up para segredo, disable, delete e mudanças classificadas
  como sensíveis pela política do deployment.
- Não expor hash, referência de token, payload, segredo resolvido ou
  propriedades internas.
- Redigir auditoria por campo/resultado/reason code; nunca registrar segredos,
  claims sensíveis ou URLs que contenham credenciais.
- Aplicar object-level policy ao cliente de origem e ao cliente de destino no
  clone.
- Manter antiforgery e sessão `HttpOnly` na UI incorporada.

## 10. Testes

### Unidade e integração

- matriz de grant types, endpoints, response types e requirements;
- URI válida/inválida, loopback, fragmento e origem de logout;
- scopes reservados e decisão do grant policy;
- capability por operação e MFA;
- cliente inexistente, manifesto, conflito e concorrência;
- ownership, expiração, retomada, abandono e finalização idempotente do
  rascunho;
- cada perfil gera somente uma combinação suportada de grants, permissions,
  requirements e scopes;
- issues de validação apontam sempre etapa e campo estáveis;
- rotação/clone sem exposição ou cópia de segredo;
- auditoria de sucesso, rejeição e falha;
- equivalência de resultado entre UI e API;
- MariaDB e SQLite para queries paginadas e atualização.

### Arquitetura

- UI continua sem referência a EF Core, OpenIddict managers ou stores;
- controller permanece adapter do serviço;
- nenhuma lista de defaults de protocolo diverge entre API e UI;
- nenhum DTO de leitura contém segredo/hash/reference ID;
- nenhuma rota, query string, log ou auditoria contém conteúdo sensível do
  rascunho.

### Interface

- desktop e mobile a partir de 320 px;
- navegação por teclado, foco, validação e confirmação;
- F5, deep link, Voltar e Avançar em todas as etapas;
- autosave, sessão concorrente, offline transitório e recuperação de erro;
- filtros da lista restaurados integralmente pela URL;
- campos repetíveis com zero, um e dezenas de URIs;
- catálogos de scopes vazios, extensos, indisponíveis e com itens reservados;
- barra inferior não encobre conteúdo nem conflita com teclado virtual/safe area;
- ausência de overflow horizontal em 320, 360, 390 e 430 px;
- loading, vazio, `403`, step-up, conflito, indisponível e sucesso;
- strings maiores e nomes/URIs longos;
- retorno à seção correta após salvar;
- teste de descoberta entre `/manage` e `/management`.

### Regressão OAuth/OIDC

- authorization code + PKCE;
- refresh token e `offline_access`;
- client credentials;
- device flow;
- PAR quando habilitado;
- login/logout front e back-channel;
- clientes legados continuam válidos antes e depois da atualização.

## 11. Rollout

1. Publicar novos contratos de leitura e `IsManifestManaged` sem alterar
   comportamento.
2. Implantar validator/policy em shadow mode e observar decisões.
3. Publicar armazenamento/API de rascunho e rotina de limpeza sem expor a rota
   na navegação.
4. Habilitar o configurador guiado para operadores do Castrum por feature flag e
   comparar criação, abandono, erro por etapa e tempo até conclusão.
5. Tornar o configurador o caminho padrão e manter o formulário antigo por uma
   janela curta de rollback.
6. Publicar API de update protegida, inicialmente sem link na UI.
7. Habilitar edição guiada no Castrum e validar clientes representativos.
8. Liberar na produção com capabilities explícitas.
9. Ativar rotação/clone apenas após Vault/secret reference operacional.
10. Adicionar recursos avançados em lotes pequenos, medindo erros de protocolo.

Rollback deve preservar schema e clientes; esconder a ação de UI não pode ser o
único mecanismo de rollback de uma policy de protocolo.

## 12. Critérios de aceite

- Um operador escolhe um perfil sem precisar conhecer grants, response types ou
  endpoint permissions para começar.
- Cada etapa possui URL própria; F5, Voltar, Avançar e retomada posterior mantêm
  o rascunho e a posição correta.
- Filtros da lista são reproduzíveis por URL sem carregar dados sensíveis.
- Scopes, grants e URIs usam controles estruturados, explicações e validação
  contextual; não dependem de texto livre genérico.
- Todo erro indica campo, motivo e correção antes da criação, e o servidor
  revalida o mesmo contrato na confirmação.
- A revisão explica em linguagem humana o acesso resultante e permite inspecionar
  a configuração OAuth/OIDC derivada.
- Nenhum segredo ou conteúdo sensível aparece em URL, histórico, rascunho em
  claro, log, métrica ou auditoria.
- O configurador opera sem overflow horizontal desde 320 px, com ações
  alcançáveis por toque e teclado e sem conteúdo encoberto.
- Um operador autorizado consegue localizar e editar uma aplicação sem usar
  SQL, manifesto manual ou acesso direto ao banco.
- UI e API produzem exatamente o mesmo resultado e auditoria.
- Um cliente de manifesto não pode ser alterado manualmente.
- Nenhuma operação retorna ou registra segredo.
- O operador não consegue conceder scope reservado ou fora de sua autoridade.
- Defaults globais de segurança não podem ser enfraquecidos por uma aplicação.
- Claims de usuário continuam funcionando e permanecem separadas de claims do
  cliente e de regras empresariais.
- A interface funciona em desktop e mobile e explicita autoridade, impacto,
  sucesso e recuperação.
- Fluxos existentes continuam interoperáveis após a edição.

## 13. Arquivos principais para retomada

Identity atual:

- `src/management/Clients/ClientManagementService.cs`
- `src/management/Controllers/ClientsController.cs`
- `src/management/Authorization/ManagementAuthorization.cs`
- `src/ui/Sufficit.Identity.UI.Management/Clients/ManagementClientDataSource.cs`
- `src/ui/Sufficit.Identity.UI.Management/Components/Pages/Clients.razor`
- `src/ui/Sufficit.Identity.UI.Management/Components/Pages/ClientCreate.razor`
- `src/ui/Sufficit.Identity.UI.Management/Components/Pages/ClientDetail.razor`
- `src/ui/Sufficit.Identity.UI.Management/wwwroot/app.css`
- `src/core/Data/AppDbContext.cs`
- `src/core/Entities/` — nova entidade de rascunho
- `src/core/Migrations/` — persistência/limpeza do rascunho
- `src/management/Provisioning/OpenIddictManifestProvisioner.cs`
- `src/application/Sufficit.Identity.Application.Abstractions/Management/Provisioning/IdentityProvisioningManifest.cs`
- `docs/plans/PLAN-GLM-5-2-REMAINING.md` — P0.2
- `docs/architecture/ARCHITECTURE-MANAGEMENT-AUTHORIZATION.md`
- `docs/design/DESIGN-MANAGEMENT-UI.md`

Legado usado como evidência funcional:

- `src/Skoruba.Duende.IdentityServer.Admin.UI.Client/src/pages/Client/Edit/`
- `src/Skoruba.Duende.IdentityServer.Admin.UI.Client/src/services/ClientServices.ts`
- `src/Skoruba.Duende.IdentityServer.Admin.UI.Api/Controllers/ClientsController.cs`
- `src/Skoruba.Duende.IdentityServer.Admin.UI.Api/Dtos/Clients/ClientApiDto.cs`
- `docs/Images/client-edit.png`
- `docs/Images/client-summary.png`

## 14. Próximas etapas pendentes

Este arquivo registra somente trabalho ainda pendente. Entregas concluídas
foram movidas para `docs/activities/`.

### Fase 0 — contratos e políticas restantes

Os contratos compartilhados, a policy de scopes e as transições do
provisionamento foram concluídos e estão registrados em
[`202608081900-completed-client-provisioning-lifecycle.md`](../activities/202608081900-completed-client-provisioning-lifecycle.md).

- [ ] Inventariar os manifests reais de produção e adotar clientes existentes
  individualmente antes de habilitar `Enforce`.
- [ ] Derivar o catálogo de perfis das features efetivamente habilitadas no
  runtime.

### Fase 3 — ciclo de vida operacional

- [ ] Paginar e pesquisar aplicações no servidor, mantendo filtros reproduzíveis
  pela URL.
- [ ] Implementar clonagem segura sem copiar segredos, tokens, autorizações ou
  propriedades de manifesto.
- [ ] Implementar habilitação/desabilitação somente quando houver enforcement
  real no runtime.
- [ ] Implementar metadados e rotação de client secret por `SecretReference`
  com Vault, sem exibir segredo na API ou na auditoria.
- [ ] Definir claims e propriedades tipadas da aplicação com allowlist e
  política de emissão.

### Fase 4 — validação visual e rollout

- [ ] Executar inspeção visual automatizada em 320, 360, 390 e 430 px.
- [ ] Validar teclado, foco, teclado virtual, deep link, F5 e concorrência na
  edição guiada.
- [ ] Publicar a capability de atualização por deployment e validar clientes
  representativos antes de habilitar em produção.
