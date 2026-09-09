# Autenticação de sistemas parceiros: núcleo e simulação

O núcleo permite uma credencial de sistema com vencimento de um ano desde a
primeira credencial. O backend usa `client_credentials` para obter access tokens
curtos repetidamente. A simulação configura 15 minutos; o segredo anual não é
um access token anual.

A implementação é genérica. Nomes comerciais, identificadores de parceiros,
carteiras e permissões pertencem ao cadastro/configuração de cada integração.

## Identidades e autoridade

- O administrador humano tem uma conta individual. Administrar uma empresa
  parceira não significa administrar o provedor Identity.
- A aplicação tem seu próprio `client_id`, segredo e concessões explícitas.
  O `sub` do token de sistema identifica a aplicação, não o humano. Não há
  cópia automática das permissões do administrador.
- Um operador interno autorizado cria/configura a aplicação. O parceiro não
  recebe `identity.clients.create/update`, nem administração global de usuários.
- A associação de negócio entre parceiro, administrador, aplicação e carteira
  ainda precisa de um fluxo próprio na camada Sufficit. Esta entrega não cria
  hierarquia de empresas dentro do Identity.

A superfície `/api/service-accounts` existente cria contas para administrar o
próprio Identity e inclui seu escopo administrativo. Não é o perfil usado nesta
simulação de uma integração de negócio.

## Cadastro pelo operador interno

A API de gestão exige autenticação, escopo administrativo e as capacidades
correspondentes. As requisições abaixo são modelos para uma operação futura
em ambiente autorizado, não registros feitos em produção. Substitua os valores
entre `<...>`; use escopos de recurso previamente cadastrados e aprovados.

1. `POST /api/clients`: criar registro sem segredo e sem grants. Ele fica inerte
   até a configuração terminar.

   ```json
   {
     "clientId": "<identificador-da-aplicacao>",
     "displayName": "Integração de sistema",
     "grantTypes": [],
     "scopes": [],
     "redirectUris": []
   }
   ```

2. `POST /api/clients/<clientId>/credentials`: usar `version` da resposta anterior.
   Para o vencimento, calcular a data UTC correspondente a um ano a partir do cadastro.

   ```json
   {
     "expectedClientVersion": "<version>",
     "label": "Integração anual",
     "generate": true,
     "expiresAtUtc": "<data-UTC-ISO-8601>"
   }
   ```

   O resultado traz `oneTimeSecret` uma única vez. Guardá-lo no cofre de segredos
   do backend. A primeira credencial com datas fica em `oauthclientcredentials`,
   com hash, identificador, validade e versão; `applications.ClientSecret` fica
   vazio. `createdAsPrimary=false` é esperado. A aplicação passa a confidencial.
   `notBeforeUtc` permite agendar a ativação. O limite existente de validade é
   730 dias.

3. `PUT /api/clients/<clientId>`: habilitar o fluxo de sistema. Usar
   `overview.clientVersion` retornado na criação da credencial, ou recarregar
   a versão atual antes de alterar.

   ```json
   {
     "displayName": "Integração de sistema",
     "expectedVersion": "<clientVersion>",
     "grantTypes": ["client_credentials"],
     "scopes": ["<escopo-do-recurso>"],
     "redirectUris": [],
     "accessTokenLifetimeMinutes": 15
   }
   ```

4. Conceder somente os recursos aprovados. O STS já lê
   `identity:client:entitlements` das propriedades da aplicação e emite os claims
   `entitlements` e `directive`. A simulação grava essa propriedade pelo manager
   interno como fixture. **Não foi criada uma API de carteira nem uma API para
   o parceiro escrever suas próprias concessões.**

A criação inicial sem datas mantém o comportamento legado: segredo principal
sem validade. Para o perfil anual, informar `expiresAtUtc` já no passo 2.
Aplicações antigas com segredo principal não são convertidas automaticamente;
acrescentar um segredo anual não invalida o principal que já existia.

## Comunicação entre os sistemas

O backend envia `POST /connect/token`, formulário URL-encoded com:

```text
grant_type=client_credentials
client_id=<identificador-da-aplicacao>
client_secret=<segredo-do-cofre>
scope=<escopo-do-recurso>
```

Usa `Authorization: Bearer <access_token>` na API de recurso, mantém o token
em cache e solicita outro antes do fim de `expires_in`. Não há login interativo
nem refresh token neste fluxo. O segredo de sistema permanece no backend,
separado das credenciais SIP/WebRTC do webphone.

Na simulação, o formato JWT é habilitado apenas para o cliente fictício, por
`Sufficit:Identity:Tokens:AccessTokenFormatsByClient:<clientId> = Jwt`. A assinatura,
issuer, audience e validade são verificados pelo JWKS publicado pelo servidor
de testes. Isso não altera o formato padrão de produção: o formato e o recurso
precisam ser compatíveis com a API consumidora.

## Rotação e revogação

`GET /api/clients/<clientId>/credentials` retorna metadados, nunca o segredo.
Criar a substituta, trocar o segredo no backend, verificar nova emissão e revogar
a antiga usando:

```text
POST /api/clients/<clientId>/credentials/<credentialId>/revoke
```

```json
{
  "expectedCredentialVersion": "<version-da-credencial>",
  "reason": "Rotação concluída"
}
```

Agendamento, vencimento e revogação são conferidos ao autenticar a aplicação.
Revogar o segredo bloqueia **novas emissões**; não desfaz por si só access tokens
já emitidos. Alterar concessões também não reescreve um JWT existente. Para
bloqueio imediato em todas as APIs, será necessário verificar o mecanismo de
revogação/introspecção efetivamente usado por cada consumidor.

## Executar a simulação local

Na raiz do repositório, com o SDK indicado em `global.json`:

```bash
dotnet test src/tests/Sufficit.Identity.Tests.csproj \
  -p:SufficitUseLocalSui=false \
  -p:TreatWarningsAsErrors=true \
  --filter FullyQualifiedName~PartnerAuthorizationSimulationTests
```

São sete casos, em SQLite em memória, sem bypass de autorização. Criam um
usuário fictício e aplicações; exercitam os serviços reais de gestão e o endpoint
HTTP de token. O bootstrap interno recebe somente as capacidades de gestão
necessárias ao teste. A conta humana não recebe papel de administrador global.
Os segredos e tokens são temporários, não são exibidos nem salvos como credencial
operacional reutilizável.

A cobertura verifica emissão/renovação, assinatura e validade do token,
concessão explícita, ausência de herança humana, negativa de administração e de
criação de credencial pelo próprio parceiro, segredo incorreto/de outro cliente,
agendamento, expiração, revogação, substituição e preservação de outras regras
de validação.

## Limites e próxima implementação Sufficit

A prova de concessão por contexto nesta entrega termina no token: ela verifica
quais claims chegam assinados. Não exercita uma chamada real à API de telefonia,
um histórico de chamadas nem uma chamada SIP.

Para o próximo incremento funcional:

1. Definir na camada de negócio o vínculo aplicação → parceiro → clientes
   autorizados, incluindo revogação e aprovação interna de concessões. Reusar
   os cadastros existentes onde forem adequados, sem criar nomes específicos
   de um parceiro no código.
2. Integrar essa concessão com a API de telefonia: testar recurso permitido e
   recurso de outro cliente, emissão de credencial de ramal e consulta de
   histórico. O endpoint de provisionamento hoje restrito a cliente interno
   não deve ser liberado globalmente para parceiros.
3. Conectar o backend do parceiro e seu webphone a um ambiente de homologação,
   com dados e credenciais próprios desse ambiente.

Separação interna de PABX por cliente, bloqueio de discagem entre ramais e
consulta de operadora para o parceiro continuam fora desta etapa. Titularidade
e autorização da linha continuam no fluxo de negócio; o token de aplicação não
substitui a autorização do titular.
