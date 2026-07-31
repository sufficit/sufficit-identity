# Single-source UI architecture

> Decisão confirmada e refinada em 2026-07-29.
>
> Este é o documento canônico para a fronteira entre as interfaces e o
> domínio do Sufficit Identity. A camada de aplicação é a única fonte de
> verdade em runtime; a API HTTP é um de seus adaptadores.

## Regra

Toda informação operacional exibida ou alterada por uma UI deve passar pelo
mesmo contrato de aplicação usado pelos controllers da API. Isso vale para a
UI pública, a área de autoatendimento e a Management UI.

Uma Razor Class Library incorporada ao mesmo processo pode resolver esses
use cases por DI. Ela não precisa fazer uma chamada HTTP ao próprio host.
O requisito é reutilizar a mesma implementação, validação, autorização e DTO,
sem criar um caminho paralelo.

A UI nunca acessa diretamente banco, `DbContext`, `UserManager`,
`SignInManager`, gerenciadores do OpenIddict ou SDKs de infraestrutura.

## Responsabilidades

A camada de aplicação é proprietária de:

- dados de contas, clientes, scopes, grants, sessões, branding e auditoria;
- identidade do operador e capabilities efetivas;
- exigências de MFA e políticas administrativas do provedor;
- opções, estados, regras de validação e defaults de protocolo;
- paginação, filtros autorizados e resultados de comandos;
- códigos estáveis de erro, autorização e recuperação;
- contratos consumidos por todos os adaptadores.

A UI é proprietária somente de:

- composição visual, acessibilidade e comportamento de apresentação;
- strings estritamente visuais e localização;
- estado transitório de interação, como campo em edição e painel aberto;
- adaptação responsiva dos DTOs recebidos;
- escolha de quais ações apresentar a partir das capabilities retornadas pelo
  use case canônico.

A UI não mantém uma segunda matriz de capabilities, lista de opções de
negócio, default de segurança ou cópia autoritativa de um
recurso.

## Adaptadores permitidos

```text
UI incorporada
   │ DI
   ▼
contrato/use case de aplicação ◄── controller da API ◄── HTTP/bearer
   │
   ├── autorização e política MFA
   ├── validação e auditoria
   └── acesso a Identity / OpenIddict / persistência
```

O controller deve ser fino: traduz transporte HTTP para o mesmo comando ou
consulta usado pela UI. A UI incorporada pode chamar o contrato diretamente
com a sessão do host. Automação externa chama o controller por HTTP.

Uma UI fora do processo usa HTTP e um cliente tipado. Uma UI no mesmo processo
pode usar HTTP quando houver motivo operacional, mas isso não é requisito de
consistência.

## Convenção de URLs da UI

As páginas da Management UI usam caminhos estáveis para identificar a
funcionalidade. Identificadores, filtros e o contexto da operação são
transportados preferencialmente pela query string, em vez de criar hierarquias
variáveis no caminho.

Claims continuam obrigatoriamente contextuais a um usuário, mas usam:

- `/management/claims?user={userId}` para consulta;
- `/management/claims/new?user={userId}` para criação;
- `/management/claims/edit?user={userId}&claim={claimId}` para edição.

Sem o parâmetro `user`, a interface falha fechado e orienta o operador a
selecionar uma conta; ela nunca converte a ausência do contexto numa listagem
global. Essa convenção é de navegação da UI e não altera os recursos REST
publicados pelos adaptadores HTTP.

## Autorização

- Controllers e UIs usam o mesmo avaliador de capabilities e recursos.
- Policies de rota podem melhorar challenge, navegação e explicações, mas não
  redefinem a decisão de negócio.
- O use case recebe o operador e o recurso real, aplica a capability e a
  política MFA e falha fechado.
- Cookie interativo e bearer são autenticações diferentes na borda, não regras
  de autorização diferentes no domínio.
- A UI não recebe access token ou refresh token apenas para chamar o próprio
  runtime.

## Contratos

- Interfaces, comandos, consultas, resultados e DTOs canônicos são definidos
  uma vez na camada de aplicação.
- A API publica esses contratos em HTTP/OpenAPI sem reimplementar as regras.
- Clientes remotos podem ser gerados a partir do OpenAPI.
- DTOs estritamente visuais podem projetar um resultado, mas não redefinem
  regras de negócio.
- Respostas distinguem `unauthenticated`, `denied`, `step-up-required`,
  `not-found`, conflito, validação e indisponibilidade.

## Violações atuais conhecidas

Os verticais administrativos de clientes, branding, contas, claims, scopes,
sessões, autorizações e descoberta do runtime aplicam o padrão canônico.
Controllers HTTP e data sources da UI usam
`IClientManagementService`, `IBrandingManagementService` e
`IUserManagementService`, `IClaimManagementService` e
`IScopeManagementService`, `ISessionManagementService`,
`IAuthorizationManagementService` e `IManagementOverviewService` para executar
os mesmos casos de uso. Esses
serviços concentram validação, defaults, autorização e auditoria; o escopo DI curto
protege o circuito Blazor sem criar uma segunda implementação. Usuários incluem
acesso, pesquisa paginada global, detalhe, criação, atualização de perfil,
reset de senha, bloqueio, desbloqueio e exclusão segura:
a UI recebe a decisão de capability e apenas envia o comando; Identity,
confirmações, security stamp, tokens, autorizações e auditoria permanecem no
runtime canônico.

O adaptador SCIM publica Users e Groups em `/scim/v2`. Ele não é uma segunda
fonte de contas: Users projetam o mesmo ASP.NET Identity e as mutações de
ativação, revogação e exclusão passam pelo mesmo
`IIdentityAccountLifecycleService` usado pelo Management. Groups possuem
persistência SCIM própria e opaca, deliberadamente separada de roles e
autoridades empresariais.

Claims são atribuições persistidas nas contas. Sua criação, edição e remoção
atualizam o security stamp e revogam tokens pelo serviço de aplicação; o valor
nunca é duplicado na auditoria. A interface de claims existe no contexto do
detalhe de cada usuário e transporta esse contexto na query string, sem uma
lista global paralela. Scopes são definições
do OpenIddict. A UI distingue
scopes criados manualmente dos marcados pelo manifesto de provisionamento:
estes últimos são somente leitura, porque sua fonte autoritativa é o próprio
manifesto. O serviço também impede excluir um scope ainda autorizado para
clientes.

Sessões projetam somente metadados não sensíveis das credenciais persistidas
pelo OpenIddict. A revogação individual atinge a credencial selecionada; o
encerramento total de uma conta também gira o security stamp e revoga tokens e
autorizações. Autorizações projetam grants/consentimentos, scopes e contagem de
credenciais. Sua revogação também revoga as credenciais relacionadas. Payload,
reference ID e conteúdo de tokens nunca atravessam o contrato de aplicação.

O overview administrativo projeta ambiente, transporte HTTP, política MFA,
capabilities efetivas e catálogo de módulos. Home, Settings, layout e navegação
consomem essa mesma projeção; não mantêm indicadores locais de prontidão. Um
módulo indisponível não aparece na navegação e conserva no contrato um
`reasonCode` estável para diagnóstico.

Provisionamento também atravessa essa fronteira. Controller HTTP e UI
incorporada chamam `IProvisioningManagementService`; o adapter Blazor converte
somente o JSON em contrato tipado. Validação, preview, autorização, resolução
de referências externas, transação de aplicação e auditoria permanecem no
runtime canônico. A UI invalida o preview quando o texto muda e exige uma
confirmação explícita antes do apply, sem manter estado de persistência
paralelo.

O avatar do operador também segue essa fronteira. A UI pública e a Management
UI resolvem a imagem por `IUserAvatarUrlResolver`, que consome o tema ativo
armazenado no runtime e aplica o `AvatarUrlTemplate` uma única vez, com o
identificador codificado para URL. A origem HTTP configurada no tema continua
responsável por entregar e armazenar em cache a imagem; as UIs apenas exibem o
resultado e usam as iniciais quando não existe imagem ou seu carregamento
falha.

O primeiro vertical de autoatendimento foi migrado em 2026-07-30.
Perfil, troca de senha, exportação de dados pessoais e exclusão da própria
conta usam `IAccountSelfService`. O contrato recebe somente o principal
autenticado e DTOs imutáveis; sua implementação no STS concentra validação,
Identity e atualização do cookie interativo. A exclusão reutiliza
`IIdentityAccountLifecycleService`, revogando tokens e autorizações antes de
remover a conta. As páginas `/manage`, `/manage/changepassword`,
`/manage/personaldata` e `/manage/deleteaccount` não recebem entidades
mutáveis nem gerenciadores de persistência.

O vertical de acessos da própria conta foi migrado em 2026-07-31 para
`IAccountAccessService`. Aplicações conectadas e sessões deixaram de projetar
a mesma coleção de autorizações. `/manage/grants` agrupa por aplicação as
autorizações válidas, une seus scopes e informa a quantidade de credenciais
ativas; revogar o acesso invalida todas as autorizações do usuário para aquela
aplicação e os tokens relacionados. `/manage/sessions` projeta credenciais
OpenIddict válidas e não expiradas, sem payload ou reference ID; a revogação
individual afeta somente a credencial selecionada, enquanto o encerramento
total gira o security stamp e revoga tokens e autorizações. Em todas as
mutações, o runtime verifica a propriedade do recurso pelo principal
autenticado e falha fechado para identificadores pertencentes a outra conta.

Ainda existem violações a migrar:

- fluxos públicos de login, cadastro, confirmação de e-mail e recuperação de
  senha ainda injetam `UserManager` e `SignInManager`;
- consentimento, logins externos, 2FA e passkeys ainda
  recebem gerenciadores do Identity/OpenIddict.

Esses caminhos são débitos de migração, não precedentes arquiteturais. Nenhuma
nova tela deve repetir esse padrão.

## Ordem de migração

1. Migrar configurações e provisionamento para use cases compartilhados
   (branding concluído em 2026-07-29; claims, scopes, sessões, autorizações e
   provisionamento, exclusão de conta e ciclo de vida SCIM concluídos em
   2026-07-30).
2. Criar contratos de aplicação para autoatendimento e migrar a UI pública
   (perfil, senha, dados pessoais e exclusão concluídos em 2026-07-30;
   aplicações conectadas e sessões concluídas em 2026-07-31).
3. Remover das UIs referências a entidades mutáveis, stores e gerenciadores de
   persistência/protocolo. Permanecem permitidos contratos puros de aplicação,
   como `IUserAvatarUrlResolver`, resolvidos pelo composition host.
4. Adicionar testes arquiteturais que falhem quando uma UI ou controller
   reimplementar validação ou acessar dependências proibidas.

## Critérios de aceite

- UI incorporada e controller executam a mesma implementação de cada use case.
- Nenhuma assembly de UI referencia EF Core, Identity stores, OpenIddict
  managers ou SDKs de infraestrutura.
- Controllers não contêm validações ou defaults de negócio ausentes no
  contrato de aplicação.
- Nenhuma capability ou default de segurança é decidido apenas
  no frontend.
- Testes cobrem o contrato uma vez e verificam a adaptação de UI e HTTP.
- Trocar o adaptador de UI ou HTTP não altera o resultado do domínio.
- Estados de loading, vazio, erro, acesso negado e step-up refletem resultados
  reais do use case.
- A URL de avatar é resolvida pelo mesmo contrato em todas as UIs; nenhuma tela
  lê o tema ou substitui `AvatarUrlTemplate` localmente.
