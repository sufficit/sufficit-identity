# Investigação de prontidão para migração do serviço de identidade

**Data do levantamento:** 22 de julho de 2026

**Escopo:** comparação entre o serviço de identidade em produção e o código atual de `sufficit-identity`

**Conclusão:** **NO-GO para substituição direta no estado atual**

> Este documento não contém senhas, hashes de senha, chaves privadas, tokens, segredos OAuth nem dados pessoais. Contagens de banco e tráfego são uma fotografia do momento do levantamento e podem variar até o corte.

## 1. Resumo executivo

A direção arquitetural atual está correta: `Sufficit.Identity.Server` deve ser o único host executável e composition root; `STS` deve fornecer a API e os fluxos de identidade; `Management` deve fornecer a API de gerenciamento; e `Core` deve concentrar contratos e classes compartilhadas. Essa separação já está refletida no código local.

Isso, porém, não torna o novo serviço uma substituição compatível com a produção. A produção ainda combina três aplicações — STS, Admin UI e Admin API — apoiadas em Duende IdentityServer/Skoruba, enquanto o novo host usa ASP.NET Core Identity e OpenIddict. A troca de protocolo e de modelo de persistência produz diferenças observáveis para clientes, usuários, operadores e tokens já emitidos.

Os principais bloqueadores são:

1. **Banco e provider sem combinação suportada:** a produção usa MariaDB 10.4, já fora de suporte, enquanto o código novo usa o provider Oracle `MySql.EntityFrameworkCore`, documentado para MySQL 8.0 ou superior. Oracle provider sobre MariaDB 10.4 não é uma base aceitável para produção.
2. **Credenciais de clientes incompletas:** a base OpenIddict possui 25 aplicações, mas nenhuma credencial `client_secret`; existem 10 clientes confidenciais no legado e 9 aplicações marcadas como confidenciais na nova base. Os fluxos confidenciais não sobreviverão ao corte dessa forma.
3. **Clientes e fluxos ativos incompatíveis:** tráfego real ainda usa `hybrid` e `implicit`, enquanto o novo servidor os rejeita intencionalmente. O cliente mais ativo da amostra usa `code id_token`. Um cliente móvel existente em produção nem sequer está na base nova.
4. **Formato de access token incompatível:** 26 dos 27 clientes legados emitem JWT e apenas um usa reference token. O novo default está configurado para reference token; se essa opção for desligada sem outra mudança, o OpenIddict emitirá JWE criptografado por padrão, e não o JWS assinado esperado pelos consumidores legados.
5. **Schema não reproduzível:** a base legada registra 17 migrations; a base `identity2` não registra nenhuma migration e o repositório não contém migrations EF. O schema atual não pode ser recriado ou promovido de maneira auditável.
6. **Regressões de política e login:** os requisitos de conta confirmada, e-mail único e senha mínima de produção não foram reproduzidos. A tela pede e-mail, mas a autenticação usa username; 121 usuários legados têm username normalizado diferente do e-mail normalizado.
7. **Proxy e CORS incompletos:** não há CORS no host novo apesar de 29 origens registradas nos clientes legados. A configuração sugerida de proxies confiáveis omite o loopback usado pelo Nginx, o que pode invalidar `X-Forwarded-*`, provocar redirects incorretos e agrupar o rate limit no endereço do proxy.
8. **Chaves e continuidade de sessão/token não resolvidas:** OpenIddict exige material de assinatura e criptografia coerente entre os nós. O mecanismo atual de chaves automáticas do Duende não pode ser reutilizado diretamente. A cópia do key ring de Data Protection, isoladamente, também não garante que cookies legados sejam aceitos.
9. **Gerenciamento sem paridade:** a API nova oferece quatro operações de clientes. A Admin API de produção publica 73 caminhos e 116 operações, abrangendo clientes, recursos, escopos, usuários, papéis, grants, chaves, logs e diagnóstico.
10. **Entrega e cluster não reproduzíveis:** os três nós executam artefatos e frameworks diferentes; não há pipeline de imagem/publicação/deploy do novo host; um dos nós roda Ubuntu 20.04, não suportado pelo .NET 10 para instalação direta.

O resultado verde dos testes locais — 33 testes aprovados — é útil, mas não altera o NO-GO: parte desses testes afirma explicitamente que clientes reais de produção são rejeitados. Eles comprovam o comportamento implementado, não a compatibilidade do corte.

## 2. Escopo e método

O levantamento combinou:

- inspeção do código, testes, Dockerfile, workflow de CI e documentação dos repositórios `sufficit-identity` e `sufficit-identity-ui`;
- build e testes locais em Release;
- inventário somente leitura dos três nós de aplicação, proxy, units systemd, listeners, runtimes e versões do sistema operacional;
- inspeção somente leitura dos metadados OIDC públicos, health checks e Swagger;
- comparação agregada e sem PII das bases `identity` e `identity2`;
- consulta à documentação primária do .NET, ASP.NET Core, OpenIddict, Duende, Oracle MySQL Connector, Pomelo e MariaDB.

Não foram executadas alterações em produção. Também não foi feita prova de carga nem corte experimental de tráfego.

## 3. Estado atual em produção

### 3.1 Topologia observada

Cada um dos três nós de aplicação mantém três units ativas:

| Componente | Diretório | Listener atual | Papel |
|---|---|---:|---|
| Identity/STS | `/opt/sufficit-identity` | `0.0.0.0:26501` | autenticação e emissão de tokens |
| Identity Admin | `/opt/sufficit-identity-admin` | `127.0.0.1:26504` | interface administrativa |
| Identity Admin API | `/opt/sufficit-identity-api` | `0.0.0.0:26601` | gerenciamento |

O Nginx de cada nó termina TLS e encaminha para listeners locais. O HAProxy possui um backend de identidade com os três nós e verifica `HEAD /health` por TLS na porta interna do proxy. Entretanto, o DNS público do hostname de identidade apontava diretamente para um único nó no momento da investigação, não para o HAProxy. Assim, a redundância configurada não estava efetivamente no caminho público observado.

Recomendações operacionais imediatas:

- fazer STS e Admin API escutarem somente em loopback ou rede explicitamente necessária, pois o Nginx é local;
- documentar e testar qual é o caminho canônico: DNS → HAProxy → Nginx → Kestrel;
- usar `/health/ready` para retirada de tráfego e manter `/health` como liveness, em vez de rotear somente por liveness;
- eliminar o `sleep 35` fixo do pre-start e substituí-lo por dependências/readiness verificáveis;
- corrigir helpers de pre-start ausentes. Hoje algumas units ignoram falha de helper e continuam iniciando.

### 3.2 Drift entre nós

Os nós não executam o mesmo artefato:

- um nó já contém STS self-contained em .NET 10, Skoruba 3.0 e Duende 7.4.7;
- dois nós permanecem em .NET 9, Skoruba 2.7 e Duende 7.3.2;
- Admin e Admin API permanecem em .NET 9/Skoruba 2.7;
- metadados de discovery diferem entre o nó mais novo e os nós de standby;
- hashes de configurações e artefatos-base diferem.

As chaves públicas JWKS observadas eram iguais, o que preserva a validação dos tokens legados entre os nós. Ainda assim, o drift de runtime, dependências e discovery torna imprevisível um failover. Antes da migração, os três nós precisam receber um artefato imutável, com o mesmo digest e a mesma configuração versionada por ambiente.

### 3.3 Plataforma

| Nó | Sistema operacional observado | Implicação para .NET 10 |
|---|---|---|
| Primário | Ubuntu 24.04 | suportado |
| Standby 1 | Ubuntu 24.04 | suportado |
| Standby 2 | Ubuntu 20.04 | não consta na matriz suportada do .NET 10 |

Nenhum dos nós possuía runtime .NET 10 instalado durante o inventário, embora um artefato self-contained já estivesse rodando. Para o novo serviço há duas opções válidas: publicar explicitamente como self-contained/container para uma plataforma suportada, ou instalar runtime suportado após atualizar o sistema operacional. Apenas informar RID não deve ser tratado como garantia de publicação self-contained.

### 3.4 Banco e alta disponibilidade

A base observada é MariaDB 10.4.34. O status ao vivo mostrou cluster Galera em estado `Primary`, `Synced`, `Ready` e com quatro membros conectados. Isso contradiz um inventário estático que ainda descrevia o banco como standalone; o runbook deve refletir o estado real.

Há três problemas centrais:

1. MariaDB 10.4 encerrou seu ciclo de suporte em 18/06/2024.
2. O projeto novo referencia `MySql.EntityFrameworkCore`/`UseMySQL`, do Oracle Connector/NET, cuja documentação exige MySQL Server 8.0 ou superior; MariaDB não é a plataforma indicada.
3. O Pomelo é o provider EF historicamente compatível com MariaDB, mas a release estável observada está alinhada ao EF Core 9, não ao EF Core 10. Não se deve introduzir build nightly de provider no serviço de identidade em produção.

Portanto, é necessária uma decisão de plataforma antes de continuar:

- **Opção A — MySQL:** migrar para uma versão MySQL 8.x oficialmente suportada pelo Oracle provider, redesenhando também a estratégia HA hoje baseada em Galera/MariaDB; ou
- **Opção B — MariaDB:** atualizar para uma linha mantida, preferencialmente MariaDB 11.4 LTS, e usar um provider estável que declare compatibilidade com a versão do EF escolhida; isso pode exigir manter o serviço em EF/.NET 9 até existir uma combinação estável de EF 10.

Manter Oracle Connector/NET + MariaDB 10.4 deve ser considerado **bloqueador de produção**.

## 4. Arquitetura do código novo

### 4.1 Estrutura pretendida

O código local materializa a composição desejada:

- [`src/server/Program.cs`](../src/server/Program.cs): único host, configuração do pipeline, health checks e composição dos módulos;
- [`src/sts/ServiceCollectionExtensions.cs`](../src/sts/ServiceCollectionExtensions.cs): Identity/OpenIddict, stores, endpoints e políticas do STS;
- [`src/management/ServiceCollectionExtensions.cs`](../src/management/ServiceCollectionExtensions.cs): serviços da API de gerenciamento;
- [`src/core/Data/AppDbContext.cs`](../src/core/Data/AppDbContext.cs): contexto e classes compartilhadas;
- [`src/tests`](../src/tests): testes de fluxos e compatibilidade conhecida.

Essa nomenclatura deve ser preservada. `STS` e `Management` são módulos/assemblies, não hosts. Consequentemente, appsettings, configuração de Kestrel, logging e lifecycle pertencem ao `Server` e não devem voltar para os módulos.

### 4.2 Estado local verificado

- `dotnet test Sufficit.Identity.sln -c Release --no-restore`: **33/33 aprovados**, sem warnings;
- `dotnet list Sufficit.Identity.sln package --vulnerable --include-transitive`: nenhum pacote vulnerável conhecido nas fontes NuGet consultadas;
- não foram encontradas referências a Newtonsoft.Json; a serialização usa `System.Text.Json`;
- o repositório contém mudanças locais não commitadas da reorganização arquitetural;
- o repositório de UI está limpo, mas o workflow da API fixa um commit antigo da UI que não está no histórico remoto atual;
- não há listener local persistente na porta 26501 no momento deste relatório; a execução anterior foi parada explicitamente, não caiu por crash.

A ausência de advisory no audit de pacotes não equivale a suporte de plataforma: ela não torna a combinação Oracle Connector/NET + MariaDB 10.4 suportada.

### 4.3 Publicação e configuração

O projeto Server exclui `appsettings*.json` da publicação. Isso é adequado para impedir o embarque de segredos, desde que o deploy injete toda a configuração em tempo de execução. Hoje não existe no repositório um contrato completo de deploy que faça isso.

A senha de banco e demais segredos devem ser materializados pelo plano de controle antes do start, por exemplo com systemd credentials, secret de orquestrador ou arquivo temporário de permissão restrita. O boot da própria identidade **não pode depender de consultar dinamicamente um MCP que exige essa mesma identidade**, porque isso cria dependência circular.

## 5. Comparação de contratos OAuth 2.0/OpenID Connect

### 5.1 Grants e response types

| Capacidade | Produção | Novo Server | Impacto |
|---|---|---|---|
| Authorization Code | sim | sim | compatível após validar PKCE/redirects |
| Client Credentials | sim | sim | bloqueado por ausência de secrets |
| Refresh Token | sim | sim | semântica de rotação difere para 5 clientes |
| Device Code | sim | sim | requer ensaio E2E |
| Password | usado por 2 clientes | desabilitado por padrão | decisão de depreciação/migração |
| Implicit | usado por 3 clientes | não suportado | bloqueador para clientes ativos |
| Hybrid | usado por 3 clientes | não suportado | bloqueador; cliente dominante usa `code id_token` |
| CIBA | anunciado em produção | não suportado | medir uso antes de retirar |
| Token Exchange | grant custom legado + RFC 8693 novo | novo controlador implementa RFC 8693 | contrato e claims não equivalentes |
| JWT/SAML bearer | cadastrados no legado | não suportados | medir uso e remover ou implementar |

O discovery público legado anuncia `plain` e `S256` para PKCE. O código novo deve aceitar apenas `S256`, salvo requisito comprovado. A retirada de `plain`, `implicit`, `hybrid`, password e grants customizados é desejável do ponto de vista de modernização, mas precisa ocorrer **nos clientes antes do corte**, não silenciosamente no servidor.

### 5.2 Tráfego real

Uma amostra histórica sanitizada de aproximadamente 220 mil requisições contém:

| Endpoint | Ocorrências aproximadas |
|---|---:|
| `/connect/userinfo` | 200.768 |
| `/connect/authorize` | 11.390 |
| `/connect/introspect` | 2.553 |
| `/connect/token` | 1.222 |
| `/connect/par` | 84 |

O cliente mais presente no recorte, `SufficitWebForms`, usa hybrid `code id_token`. `SufficitEndPointsSwaggerUI` usa implicit token. Ambos são rejeitados nos testes atuais por decisão explícita. Isso demonstra que a migração exige atualização dos consumidores, e não apenas conversão de dados.

`/connect/par` também aparece no tráfego. Embora o OpenIddict possa suportar PAR, a configuração e os testes atuais não cobrem o contrato usado em produção. Deve haver teste de discovery, submissão de PAR, validade do `request_uri`, autenticação do cliente e autorização subsequente.

### 5.3 Inventário de clientes

Na fotografia do banco:

- legado: 27 clientes habilitados;
- OpenIddict: 25 aplicações;
- ausentes na base nova: `client` e `sufficit_mobile_apps`;
- 13 clientes exigem PKCE;
- 17 são públicos;
- 18 permitem offline access;
- 10 clientes legados exigem secret;
- 9 aplicações novas são classificadas como confidenciais;
- **zero** credenciais `client_secret` existem na base OpenIddict;
- redirects e post-logout redirects dos 25 clientes copiados têm contagens equivalentes;
- o cliente móvel ausente possui redirects próprios que também não foram copiados;
- um cliente legado possui claim `directive`, que o migrador/token exchange novo não reproduz.

Cada um dos 27 clientes precisa terminar em uma destas categorias documentadas:

1. migrado e validado;
2. atualizado antes do corte;
3. explicitamente descontinuado com evidência de ausência de tráfego;
4. mantido temporariamente no legado por exceção aprovada.

Não é suficiente considerar os 25 registros existentes na base nova como cobertura.

### 5.4 Access tokens, introspection e revogação

No legado, 26 clientes estão configurados para JWT e um para reference token. O novo default global usa reference access tokens. Se esse default for alterado para falso, OpenIddict ainda criptografa access tokens por padrão e produz JWE; consumidores que hoje validam JWS localmente não conseguirão processá-los.

O desenho de compatibilidade deve definir por cliente:

- reference token + introspection; ou
- JWT assinado JWS, configurando explicitamente `DisableAccessTokenEncryption()` quando necessário;
- audience, issuer, scopes e claims esperadas;
- algoritmo e rotação de signing keys;
- estratégia de revogação.

Reference token não é requisito para revogação no OpenIddict. A escolha deve ser baseada no contrato dos resource servers, e não usada como atalho global.

### 5.5 Refresh tokens

O legado tem:

- 22 clientes com refresh token rotativo/one-time;
- 5 clientes com refresh token reutilizável;
- 3.661 refresh tokens persistidos na fotografia analisada.

O OpenIddict aplica rotação. Para os cinco clientes reutilizáveis — incluindo famílias desktop, Blazor e mobile — isso pode gerar falhas concorrentes ou logout quando duas instâncias reapresentarem o mesmo token. Esses clientes precisam ser adaptados e testados antes do corte.

Os grants Duende não são convertíveis diretamente em tokens OpenIddict. Deve-se assumir invalidação dos refresh/reference tokens e nova autenticação, salvo se for construída e auditada uma ponte específica. Para esta migração, forçar reautenticação controlada é significativamente mais seguro.

### 5.6 Logout e sessões

Produção anuncia front-channel e back-channel logout. O novo serviço desabilita os recursos por padrão e os endpoints atuais são stubs sem implementação efetiva. Existem 24 clientes com flags de logout/session no legado.

Antes do corte é necessário:

- implementar e testar end-session;
- decidir suporte a front-channel e back-channel;
- validar `post_logout_redirect_uri` de cada cliente;
- testar logout distribuído e expiração de sessão;
- não anunciar metadados que o servidor não cumpre.

## 6. Identidades, claims e cookies

### 6.1 Paridade de usuários

| Métrica | Legado `identity` | Novo `identity2` | Observação |
|---|---:|---:|---|
| Usuários | 2.408 | 2.410 | 1 somente legado; 3 somente novo |
| E-mails confirmados | 2.152 | 2.152 | paridade agregada |
| Usuários com 2FA | 4 | 4 | exige teste E2E |
| Passkeys | 0 | 0 | UI nova ainda é stub |

Entre usuários comuns, os hashes de senha coincidem. Foram observadas uma divergência de security stamp e uma de access-failed count. Logins externos e roles apresentam paridade agregada. Há cinco user claims legadas ausentes na base nova.

A delta final deve ser reaplicada sob freeze ou por processo idempotente. Não se deve usar apenas as contagens atuais como prova de paridade.

### 6.2 Login por e-mail

Produção usa política de resolução por e-mail. A UI nova apresenta “E-mail”, mas chama `PasswordSignInAsync` com o valor como username. Existem 121 usuários legados cujo normalized username difere do normalized email. Para eles, informar o e-mail pode falhar mesmo com senha válida.

Correção necessária:

1. localizar usuário por `FindByEmailAsync` usando normalização do Identity;
2. autenticar a entidade encontrada sem revelar se a conta existe;
3. preservar lockout, 2FA e confirmação de conta;
4. cobrir username diferente do e-mail, casing, e-mail duplicado legado e usuário inexistente.

### 6.3 Políticas de Identity

Produção configura:

- conta confirmada obrigatória;
- e-mail único;
- senha com comprimento mínimo 8;
- registro habilitado.

O novo `AddIdentity` configura lockout, mas deixa os defaults de confirmação, e-mail único e senha. Isso enfraquece o contrato e pode permitir novas contas fora da política vigente. Os valores devem ser explicitados e testados no módulo STS.

### 6.4 Claims e minimização

As claims persistidas mais relevantes no legado incluem `directive`, `address`, `name`, `profile` e `website`. O código novo envia claims persistidas ao access token sem uma política completa por escopo. Há milhares de ocorrências de `directive` e dezenas de claims de perfil/endereço.

Isso é risco de privacidade e compatibilidade. A política recomendada é:

- `directive` somente para scopes autorizados, como `directives`/`policies`;
- profile claims somente com `profile`;
- address somente com `address`;
- roles somente com scope e audience apropriados;
- nunca copiar todas as claims do usuário indiscriminadamente;
- comparar os tokens por cliente em testes de contrato.

### 6.5 Login externo e 2FA

Google está habilitado em produção e existem 140 vínculos de login externo copiados. O template do novo host deixa provedores externos desabilitados. O deploy precisa provisionar ClientId/ClientSecret e callback sem expô-los em appsettings ou artefato.

O novo projeto possui telas de 2FA, mas o conjunto de testes do repositório não cobre os quatro usuários existentes nem recuperação/remember machine. Passkeys aparecem na UI, porém ainda são stub; não devem ser anunciadas como funcionalidade pronta.

### 6.6 Cookies e Data Protection

Os 24 registros de Data Protection foram copiados integralmente entre as bases. Mesmo assim, a continuidade de cookie não está garantida:

- produção usa cookie `.Sufficit.Identity` com domínio `.sufficit.com.br`;
- o novo host usa o cookie default do ASP.NET Core Identity e domínio host-only;
- Data Protection também depende de `ApplicationName`, purposes, versão e esquema de autenticação;
- o novo código persiste o key ring sem proteção explícita em repouso.

A recomendação é assumir logout no corte. Se continuidade de sessão for requisito obrigatório, ela precisa de um spike isolado que reproduza nome, domínio, scheme, app discriminator e pipeline criptográfico do legado. Não deve ser inferida apenas pela igualdade do key ring.

## 7. Persistência e schema

### 7.1 Estado das tabelas operacionais

| Dado operacional | Duende legado | OpenIddict novo | Consequência |
|---|---:|---:|---|
| Persisted grants | 6.277 | não equivalente diretamente | não migrar cegamente |
| Refresh tokens | 3.661 | incluídos no modelo de tokens | reautenticação recomendada |
| Authorization codes | 2.565 | transitórios | expirar no corte |
| Reference tokens | 20 | formato/store diferente | invalidar ou criar ponte |
| Consents | 31 | authorizations = 0 | consentimento precisa ser refeito |
| Device codes | 13 | store diferente | deixar expirar antes do corte |
| Server-side sessions | 1 | sem equivalência direta | invalidar |
| OpenIddict tokens | — | 3 | identificar/remover dados de ensaio antes do corte |

Dados operacionais de Duende e OpenIddict têm semântica e proteção diferentes. A migração segura deve copiar dados mestres — usuários, roles, claims, clientes, redirects, escopos e recursos — e não transmutar grants/tokens sem especificação criptográfica formal.

### 7.2 Migrations ausentes

`identity.__efmigrationshistory` contém 17 migrations do legado. `identity2.__efmigrationshistory` está vazia e não há pasta de migrations no repositório. `EnsureCreated()` é usado somente em Development e não substitui migrations em produção.

Antes de qualquer ensaio é obrigatório:

1. gerar uma baseline versionada para Core/Identity/OpenIddict;
2. provar criação do zero em banco vazio;
3. provar upgrade da baseline até a versão candidata;
4. tornar o migrador idempotente e transacional onde possível;
5. impedir que cada nó aplique migration concorrentemente no boot;
6. registrar versão de schema e checksum do artefato no deploy.

### 7.3 Conta de banco

A conta usada pela aplicação possui privilégios amplos em múltiplos schemas, autenticação legada e não exige TLS no nível observado. A migração deve criar usuário dedicado com:

- privilégios somente no schema necessário;
- credencial forte e rotacionável;
- conexão TLS verificada;
- credencial separada para migrations, caso DDL seja necessário;
- materialização via secret store, nunca em arquivo 0644/0666.

## 8. Signing, encryption e rotação de chaves

Produção usa automatic key management do Duende e compartilha a chave pública de assinatura entre os nós. O arquivo PFX presente nos hosts não está configurado como a fonte atual de assinatura. O novo OpenIddict, por sua vez, requer credenciais de assinatura e de criptografia em produção e não pode depender dos certificados de desenvolvimento.

Plano necessário:

1. gerar duas chaves RSA/certificados distintos: signing e encryption;
2. armazená-los em secret store ou mecanismo de credenciais do host, com permissão mínima;
3. distribuir o mesmo conjunto aos três nós antes de servir tráfego;
4. expor a nova signing key no JWKS antes ou durante o corte conforme a estratégia;
5. manter a chave pública antiga disponível pelo período máximo de vida dos JWTs legados, se resource servers ainda precisarem validá-los;
6. testar rotação com múltiplas chaves, emissão pela nova e validação da anterior;
7. definir rotação, owner, prazo, alerta de expiração e rollback.

Os arquivos atuais incluem configurações e material criptográfico com modos excessivamente permissivos, alguns 0644/0666. Isso deve ser corrigido antes do ensaio. A auditoria deve verificar permissões, não apenas ausência de segredos no Git.

## 9. Proxy, hostname, TLS e rate limiting

O Nginx encaminha para `127.0.0.1`, mas o template do Server lista redes externas e não inclui explicitamente `127.0.0.1/32` na coleção customizada de proxies. O código limpa os defaults quando uma lista é fornecida. Nesse cenário, os forwarded headers do Nginx podem ser ignorados.

Efeitos possíveis:

- aplicação enxerga HTTP interno e redireciona repetidamente para HTTPS;
- issuer/callbacks são construídos com esquema ou host incorretos;
- todos os usuários aparecem com o IP do proxy;
- rate limiting por IP agrupa todo o tráfego;
- logs e auditoria perdem o endereço de origem.

Correções:

- confiar apenas em `127.0.0.1/32`/`::1` quando Nginx for local, ou na rede exata do proxy efetivo;
- configurar `ForwardLimit` e simetria dos headers;
- validar `AllowedHosts` para todos os hostnames realmente servidos;
- testar spoofing de `X-Forwarded-For` conectando diretamente ao listener;
- usar bind loopback no Kestrel para impedir bypass do proxy;
- validar o certificado público no proxy e usar o certificado autoassinado do .NET somente para desenvolvimento local em `https://localhost:26501`.

O host não registra `AddCors`/`UseCors`. Há 29 origens nos clientes legados. Browser/WASM pode falhar mesmo quando authorization e token endpoints funcionam. A política deve ser derivada de allowlist explícita por cliente/origem, nunca `AllowAnyOrigin` com credenciais.

## 10. API de gerenciamento

### 10.1 Cobertura

A API de produção expõe 73 paths e 116 operations, incluindo:

- Clients;
- ApiResources e ApiScopes;
- IdentityResources e IdentityProviders;
- Users e Roles;
- PersistedGrants;
- Keys;
- Logs e Dashboard;
- ConfigurationIssues.

A implementação nova possui somente:

- listar clientes;
- obter um cliente;
- criar cliente;
- excluir cliente.

Não há update, users, roles, scopes, resources, grants, audit, logs ou key management. Logo, o Admin e a Admin API legados não podem ser retirados junto com o primeiro corte do STS, a menos que o escopo funcional seja formalmente reduzido e os consumidores aprovados.

### 10.2 Defeitos de composição atuais

Foram observados problemas adicionais:

- `RequireAuthorization=false` evita registrar a policy, mas o controller continua decorado com `[Authorize(Policy=...)]`; isso não torna o endpoint anônimo e pode causar falha de autorização/configuração;
- `RoutePrefix` não altera a rota hardcoded `/api/clients`;
- `MapControllers()` já mapeia o controller e o método do módulo tenta mapeá-lo novamente;
- existem dois tipos `ManagementOptions` em namespaces diferentes;
- os testes não habilitam nem exercitam o módulo Management.

Recomendação: separar o programa em duas ondas. Primeiro migrar o issuer/STS mantendo Admin/API legados em modo controlado; depois concluir e migrar Management. Essa separação só é válida se ambos puderem compartilhar o cadastro mestre sem escrita concorrente incompatível.

## 11. Observabilidade e operação

O código referencia Serilog, mas não configura `UseSerilog`, sinks, enrichment, correlação ou redaction. O deploy novo precisa, no mínimo:

- logs estruturados com request/correlation ID;
- métricas por endpoint, grant, client_id anonimizado/allowlisted e resultado;
- métricas de login, lockout, 2FA, token, introspection e banco;
- redaction de authorization codes, tokens, secrets, cookies e PII;
- alertas de readiness, latência, erro 5xx, falha de DB, falha de signing e expiração de certificados;
- auditoria administrativa imutável;
- dashboards comparáveis antes/depois do corte.

O incidente recente de rotação mostrou que mudar a senha no banco antes de sincronizar todas as aplicações causa indisponibilidade do discovery e do MCP dependente. O runbook deve sempre seguir: provisionar/configurar em todos os nós → validar leitura da nova versão → rotacionar no banco → restart/rollout coordenado → validação. Quando a tecnologia permitir, usar período de sobreposição de credenciais.

Também foi observado um deploy que perdeu owner do artefato durante substituição atômica e, combinado ao `sleep 35`, aparentou timeout/falha. O pipeline precisa preservar owner/mode, validar o binário antes do swap e separar claramente timeout de start de indisponibilidade real.

## 12. CI/CD e reprodutibilidade

O workflow atual executa restore, build, testes, audit e gitleaks, mas não:

- publica artefato Server;
- constrói/testa a imagem Docker;
- gera SBOM ou assina artefato;
- aplica migrations em ambiente efêmero;
- sobe MySQL/MariaDB real para integração;
- promove o mesmo digest entre ambientes;
- realiza deploy canário/blue-green;
- executa smoke tests pós-deploy e rollback automático.

Além disso, o workflow fixa o repositório UI em um commit antigo que não existe no remoto após reescrita de histórico. O build local usou o HEAD atual da UI, portanto CI e desenvolvimento não são reproduzíveis até o pin ser atualizado para um commit remoto imutável.

O Dockerfile já oferece uma boa base — host único, usuário não-root e health check — mas exige o contexto irmão da UI e ainda não participa da CI. A dependência precisa ser expressa por submodule, pacote/versionamento, checkout CI válido ou pipeline multi-repo controlado.

## 13. Matriz de riscos

| ID | Severidade | Risco | Evidência | Gate de saída |
|---|---|---|---|---|
| R1 | P0 | provider/banco não suportado | Oracle EF + MariaDB 10.4 EOL | combinação oficialmente suportada e teste em banco real |
| R2 | P0 | clientes confidenciais param | zero client secrets no OpenIddict | 100% dos confidenciais com segredo rotacionado e teste de token |
| R3 | P0 | clientes ativos rejeitados | hybrid/implicit no tráfego; testes esperam rejeição | clientes atualizados ou ausência comprovada de tráfego |
| R4 | P0 | resource servers rejeitam tokens | legado JWS; novo reference/JWE por default | matriz por cliente e validação em cada API |
| R5 | P0 | schema irreproduzível | zero migrations em `identity2`/repo | baseline e upgrades automatizados |
| R6 | P0 | falha de login/regressão de política | login por username; 121 divergências; defaults fracos | testes E2E e options equivalentes |
| R7 | P0 | indisponibilidade/issuer incorreto atrás do proxy | trusted proxy não inclui loopback | teste proxy→Kestrel, redirect, issuer e IP real |
| R8 | P0 | signing inválido entre nós | Duende keys não reutilizáveis diretamente | certificados distribuídos e rotação ensaiada |
| R9 | P1 | claims indevidas ou ausentes | claims sem filtro por scope; client claim não copiada | golden tokens por cliente/scope |
| R10 | P1 | refresh simultâneo falha | 5 clientes usam reusable token | clientes adaptados ou política compatível testada |
| R11 | P1 | logout distribuído não funciona | stubs e metadados desabilitados | testes front/back/end-session |
| R12 | P1 | UI/browser bloqueado | 29 CORS origins e nenhum CORS novo | allowlist e testes browser reais |
| R13 | P1 | administração perde funcionalidades | 4 operações novas versus 116 legadas | manter legado ou paridade aprovada |
| R14 | P1 | nó não suportado | Ubuntu 20.04 com alvo .NET 10 | upgrade ou container suportado |
| R15 | P1 | failover muda comportamento | artefatos/runtime/discovery diferentes | mesmo digest/config nos três nós |
| R16 | P1 | segredo/chave exposto localmente | arquivos 0644/0666 e appsettings com segredos | secret store e auditoria de modos |
| R17 | P2 | falsa confiança nos testes | testes verdes incluem incompatibilidade esperada | suíte de contrato baseada em produção |
| R18 | P2 | pipeline deixa de reproduzir build | pin da UI não existe no remoto | pin válido e build de imagem na CI |

## 14. Plano de migração recomendado

### Fase 0 — Decisões bloqueantes

Antes de implementar mais código, aprovar quatro decisões:

1. MySQL 8.x + Oracle provider ou MariaDB mantido + provider/EF oficialmente compatível;
2. reautenticação obrigatória no corte, invalidando grants/tokens antigos;
3. atualizar/descontinuar clientes hybrid, implicit, password e grants customizados;
4. manter Admin/Admin API legados temporariamente ou financiar paridade funcional do novo Management.

**Saída:** Architecture Decision Records aprovados, owners e datas.

### Fase 1 — Fechar os P0 de engenharia

1. Implementar migrations versionadas e migrador idempotente.
2. Corrigir políticas de Identity e login por e-mail.
3. Implementar política de claims por scope/audience.
4. Definir token format por cliente e compatibilidade JWS/reference.
5. Provisionar/rotacionar client secrets sem copiar hashes legados como segredo utilizável.
6. Copiar os dois clientes faltantes ou registrar descontinuação.
7. Corrigir forwarded headers, bind, AllowedHosts, CORS e rate limiting.
8. Provisionar signing/encryption keys e plano de rotação.
9. Implementar logout necessário.
10. Corrigir composition/options/tests de Management ou congelar o módulo fora da primeira onda.

**Saída:** nenhum P0 aberto e testes de integração em banco suportado.

### Fase 2 — Rehearsal em clone sanitizado

1. Restaurar backup sanitizado em ambiente isolado.
2. Executar baseline + migrador do zero.
3. Validar todos os 27 clientes, usuários, roles, logins, claims, redirects, scopes e resources por contagem e checksum não reversível.
4. Exercitar login local, Google, 2FA, authorization code + PKCE, client credentials, refresh, device, introspection, userinfo, token exchange e logout.
5. Validar tokens nas APIs reais de homologação, não apenas no próprio STS.
6. Rodar carga com o perfil observado de userinfo/authorize/introspect/token.
7. Ensaiar perda de um nó, rotação de key e indisponibilidade de banco.
8. Ensaiar rollback completo.

**Saída:** relatório de rehearsal aprovado e RTO/RPO medidos.

### Fase 3 — Preparação do cluster

1. Atualizar o nó Ubuntu 20.04 ou adotar imagem/container suportado.
2. Construir uma única imagem/artefato assinado e promover o mesmo digest aos três nós.
3. Materializar config e secrets antes do start.
4. Subir o novo serviço sem tráfego público e validar `/health`, `/health/ready`, discovery, JWKS e smoke tests.
5. Fazer o DNS usar explicitamente o caminho HAProxy redundante, com TTL reduzido de forma planejada.
6. Alterar o health de roteamento para readiness.

**Saída:** três nós equivalentes, healthy e ainda fora do tráfego de produção.

### Fase 4 — Cutover controlado

Divisão por `client_id` no proxy tende a ser frágil porque o identificador aparece em query, form body e etapas distintas de sessão. Para este issuer, é mais seguro um blue-green do serviço completo após atualização dos clientes.

Sequência proposta:

1. anunciar janela e congelar alterações administrativas;
2. gerar backup consistente e verificar restauração;
3. parar escritores legados;
4. executar delta final idempotente;
5. validar gates de dados;
6. ativar o novo backend no HAProxy;
7. executar smoke tests internos e externos;
8. liberar tráfego gradualmente por peso de nó, mantendo o mesmo backend/versionamento;
9. monitorar erros por grant/cliente, login, DB, latência e recursos;
10. assumir reautenticação e comunicar expiração de sessões/tokens;
11. acionar rollback se qualquer threshold for excedido.

**Saída:** SLOs estáveis durante a janela definida.

### Fase 5 — Estabilização e retirada

- manter binários, configurações e backup legado recuperáveis por no mínimo 30 dias ou conforme retenção aprovada;
- deixar Admin/API legados disponíveis somente se ainda necessários e sem acesso público desnecessário;
- remover credenciais antigas após a janela máxima de token/rollback;
- concluir migração do Management;
- revisar telemetria, incidentes e decisões;
- somente então remover units, schemas e material criptográfico antigos.

## 15. Gates objetivos de GO

A mudança só deve receber GO quando todos os itens abaixo forem comprovados:

- [ ] banco e provider formam combinação oficialmente suportada;
- [ ] migrations criam e atualizam o schema de modo reprodutível;
- [ ] os 27 clientes estão migrados, atualizados ou formalmente descontinuados;
- [ ] todos os clientes confidenciais possuem nova credencial e teste positivo;
- [ ] nenhum fluxo incompatível tem tráfego nos últimos 7 dias, ou há implementação aprovada;
- [ ] tokens de cada cliente são aceitos por seus resource servers;
- [ ] os dois clientes ausentes e a client claim legada foram resolvidos;
- [ ] política de refresh foi validada para os cinco clientes reutilizáveis;
- [ ] delta de usuários/claims foi zerada ou justificada;
- [ ] login por e-mail, lockout, confirmação, 2FA e Google passaram em E2E;
- [ ] claims são filtradas por scope/audience e comparadas por golden tests;
- [ ] CORS, proxy headers, issuer, HTTPS e IP real foram testados via cadeia pública;
- [ ] signing/encryption keys são compartilhadas, protegidas e rotacionáveis;
- [ ] decisão de reautenticação/cookies foi aprovada e comunicada;
- [ ] escopo de Management foi aprovado sem perda operacional acidental;
- [ ] os três nós executam o mesmo digest em plataforma suportada;
- [ ] readiness retira nós defeituosos do balanceamento;
- [ ] secrets não existem em Git, appsettings publicados nem arquivos world-readable;
- [ ] rehearsal, carga, failover e rollback foram executados e documentados;
- [ ] observabilidade e thresholds automáticos de rollback estão ativos.

## 16. Critérios mínimos de rollback

Executar rollback se ocorrer qualquer uma das condições aprovadas para a janela, incluindo:

- discovery/JWKS indisponível ou issuer divergente;
- aumento sustentado de erros de token/login/introspection acima do baseline;
- falha de validação de JWT em resource server crítico;
- divergência de dados após delta final;
- readiness instável em mais de um nó;
- saturação/erro de banco;
- falha de Google/2FA para usuários de controle;
- necessidade de reemitir secrets/chaves durante a janela sem procedimento ensaiado.

Rollback deve significar reativar o backend legado e restaurar sua possibilidade de leitura/escrita de forma coerente. Se o novo sistema tiver aceitado escritas, a reversão exige tratamento dessas deltas; por isso, alterações administrativas e cadastro devem permanecer congelados durante o primeiro corte.

## 17. Decisões ainda necessárias

| Decisão | Recomendação desta investigação |
|---|---|
| Banco/provider | não avançar com Oracle provider sobre MariaDB; escolher combinação oficialmente suportada |
| Sessões/tokens | corte com reautenticação explícita, sem tentativa de converter grants Duende |
| Fluxos antigos | atualizar consumidores e retirar implicit/hybrid/password antes do corte |
| Token format | preservar JWS por cliente onde APIs validam localmente; reference somente onde introspection está contratada |
| Admin/Management | migrar em onda posterior, mantendo legado restrito até paridade aprovada |
| Runtime | imagem self-contained/container suportada e idêntica nos três nós |
| Segredos | materialização pelo plano de controle antes do start; sem dependência circular do Identity/MCP |
| Tráfego | tornar HAProxy o caminho canônico e usar readiness |

## 18. Fontes primárias

- [Oracle Connector/NET — Entity Framework Core Support](https://dev.mysql.com/doc/connector-net/en/connector-net-entityframework-core.html)
- [Pomelo.EntityFrameworkCore.MySql — compatibility](https://github.com/PomeloFoundation/Pomelo.EntityFrameworkCore.MySql)
- [MariaDB Foundation — release maintenance policy](https://mariadb.org/about/)
- [OpenIddict — Encryption and signing credentials](https://documentation.openiddict.com/configuration/encryption-and-signing-credentials.html)
- [OpenIddict — Token formats](https://documentation.openiddict.com/configuration/token-formats)
- [.NET 10 — Supported OS versions](https://github.com/dotnet/core/blob/main/release-notes/10.0/supported-os.md)
- [Microsoft — Install .NET on Ubuntu](https://learn.microsoft.com/en-us/dotnet/core/install/linux-ubuntu-install)
- [Microsoft — .NET deployment defaults for RID-specific apps](https://learn.microsoft.com/en-us/dotnet/core/compatibility/sdk/8.0/runtimespecific-app-default)
- [ASP.NET Core Data Protection — key storage providers](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/implementation/key-storage-providers?view=aspnetcore-10.0)
- [ASP.NET Core Data Protection — configuration and ApplicationName](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/overview?view=aspnetcore-10.0)
- [Duende IdentityServer — Operational data](https://docs.duendesoftware.com/identityserver/data/operational/)
- [Duende IdentityServer — Automatic key management](https://docs.duendesoftware.com/identityserver/fundamentals/key-management/)
- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [ASP.NET Katana 4.2 — PKCE support for OpenID Connect](https://github.com/aspnet/AspNetKatana/releases/tag/v4.2.0)
- [Microsoft — OpenID Connect confidential web app with code flow](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/configure-oidc-web-authentication?view=aspnetcore-10.0)
- [Swashbuckle.AspNetCore — Swagger/OpenAPI tooling](https://github.com/domaindrivendev/Swashbuckle.AspNetCore)

## 19. Veredito final

O novo `Server` é a composição arquitetural correta e deve continuar sendo o único processo inicializável. O bloqueio não é de nomenclatura: é de compatibilidade e operação.

No estado observado, trocar o serviço de produção pelo novo host causaria, com alta probabilidade, falha de clientes confidenciais, rejeição de clientes hybrid/implicit, incompatibilidade de access tokens, logout de usuários, regressões de login/política, perda de funcionalidades administrativas e risco de banco não suportado. A migração deve permanecer **NO-GO** até que os P0 e os gates da seção 15 sejam fechados em rehearsal reproduzível.

O caminho recomendado é modernizar clientes e plataforma primeiro, migrar dados mestres por processo versionado, aceitar reautenticação controlada, fazer blue-green do issuer completo e deixar o Management para uma onda separada. Isso reduz o risco e evita tentar simular compatibilidade criptográfica entre Duende e OpenIddict que não está demonstrada.

## 20. Reavaliação dirigida dos clientes hybrid/implicit

Esta seção refina o item R3 após correlacionar cadastro, código realmente implantado e logs do período de 9 a 22 de julho de 2026. Ela não altera o NO-GO global, mas mostra que o bloqueio de hybrid/implicit pode ser removido **antes** da troca do issuer e sem habilitar fluxos antigos no OpenIddict.

### 20.1 Tráfego observado versus cadastro

| Cliente | Fluxo observado | Autorizações no período | Serviço real | Situação |
|---|---|---:|---|---|
| `SufficitWebForms` | `code id_token`, majoritariamente `form_post` | 8.962 válidas, além de 4 malformadas | `sufficit-web`, callback público de `www.sufficit.com.br` | bloqueador real; migrar |
| `SufficitEndPointsSwaggerUI` | `token` | 1 | Swagger UI de `sufficit-endpoints` | migrar; baixo volume |
| `skoruba_identity_admin` | `code` + `form_post` | 9 | Admin UI atual | já usa code + PKCE |
| `client` | nenhum | 0 | cadastro genérico sem redirects/scopes | não migrar; desativar após quarentena |
| `skorubaserveradmin` | nenhum | 0 | cadastro antigo de Admin | obsoleto; não confundir com cliente implantado |
| `SufficitIdentityAdminApi` | nenhum | 0 | cadastro Swagger antigo | obsoleto/inconsistente |

Também existem clientes modernos usando code, como Grafana, Quepasa, AI Server, aplicações desktop/mobile e o Admin atual. Portanto, o volume relevante de fluxo antigo está concentrado no WebForms.

O cadastro antigo dava a impressão de três clientes hybrid e três implicit porque `client` possui os dois grants e há registros administrativos antigos. Isso não corresponde ao código administrativo atualmente implantado. O Admin UI de produção usa `skoruba_identity_admin` com authorization code, PKCE e client secret; o código do Admin API usa authorization code + PKCE para Swagger.

### 20.2 Decisão arquitetural

O estado final deve ser:

- clientes web server-side: **authorization code + PKCE S256 + autenticação confidencial do cliente**;
- Swagger/browser: **authorization code + PKCE S256 como cliente público**, sem secret no browser;
- nenhum access token na authorization response;
- nenhum `implicit`, `hybrid` ou fallback `none` no novo Server;
- redirects HTTPS mínimos e específicos por ambiente;
- secrets materializados fora de Git;
- claims liberadas por scope explícito.

Essa direção segue o OAuth 2.0 Security BCP: access tokens não devem ser emitidos na authorization response e PKCE deve usar método que não exponha o verifier; hoje esse método é S256. O próprio Katana 4.2.3 usado pelo WebForms já suporta PKCE, code redemption e salvamento opcional de tokens. Não é necessário criar um protocolo paralelo ou substituir o WebForms inteiro para eliminar hybrid.

### 20.3 Migração definitiva do WebForms

O projeto [`sufficit-web`](../../sufficit-web/src/Identity/IdentityProvider.cs) é ASP.NET WebForms/.NET Framework 4.8 com `Microsoft.Owin.Security.OpenIdConnect` 4.2.3. O código atual:

- recebe `code id_token` no front channel;
- guarda o authorization code em memória com o nome incorreto `IDToken`;
- troca o code de forma tardia, quando alguma tela pede UserInfo;
- registra o próprio code em log no método `GetToken`;
- mantém access token e claims em cache local por até dois dias;
- depende de UserInfo para popular roles/diretivas.

Esse desenho é frágil mesmo antes da troca do STS: authorization code é curto e single-use, token não deve ir para log, e o cache local não sobrevive a recycle/failover entre os três nós Web.

Mudança recomendada no consumidor:

1. fixar `ResponseType = code`;
2. fixar `RedeemCode = true`;
3. fixar `UsePkce = true` e aceitar somente S256 no cadastro;
4. manter `RequireHttpsMetadata = true` em produção;
5. deixar `SaveTokens = false` para não inflar o cookie;
6. remover `GetToken(code)` e qualquer logging de code/token;
7. obter UserInfo uma vez durante o callback autenticado e incorporar somente as claims necessárias ao ticket;
8. eliminar o cache local de codes/access tokens;
9. remover `offline_access` se nenhuma chamada posterior realmente precisar de refresh token;
10. testar logout, nonce, state, correlation cookie, SameSite e recycle/failover.

O WebForms usa diretivas para autorização de páginas e objetos. O novo STS atualmente não devolve persisted claims no UserInfo e ainda envia custom claims ao access token sem gate adequado. Antes do teste contra OpenIddict, deve ser criado o contrato:

- scope canônico `directives`;
- claim `directive` no UserInfo somente quando esse scope foi concedido;
- claim `directive` no access token somente para clientes/scopes/audiences autorizados;
- `roles` somente com scope `roles`;
- golden test comparando as roles e diretivas de usuários de controle entre Duende e OpenIddict.

Para permitir rolling deploy e rollback sem enfraquecer PKCE, não é recomendável reaproveitar imediatamente `SufficitWebForms`. Ativar `RequirePkce` no mesmo cliente quebraria nós antigos que ainda enviam hybrid com code sem challenge. A opção segura é criar o client final `sufficit_web` nos dois stores:

| Campo | Valor final recomendado |
|---|---|
| Tipo | confidential web application |
| Endpoints | authorization, token e end-session |
| Grants | authorization code somente |
| Response types | code somente |
| PKCE | obrigatório, S256 |
| Scopes | `openid profile roles directives` |
| Redirect de produção | somente o callback HTTPS público efetivamente usado |
| Redirects locais | client separado de Development |
| Refresh/offline | ausente, salvo requisito comprovado |
| Secret | nova credencial no vault/secret store, nunca no manifesto |

O client antigo permanece ativo apenas no Duende durante a janela de rollback. Ele não deve ser criado no novo OpenIddict. Após todos os nós usarem `sufficit_web` e a telemetria confirmar zero tráfego no ID antigo, `SufficitWebForms` é desabilitado e depois removido.

### 20.4 Migração definitiva do Swagger de EndPoints

No [`ConfigureSwaggerOptions.cs`](../../sufficit-endpoints/src/ConfigureSwaggerOptions.cs), o OpenAPI declara `Implicit`. Em [`StartupHelpers+Swagger.cs`](../../sufficit-endpoints/src/Helpers/StartupHelpers+Swagger.cs), a UI configura apenas client ID e scopes.

Mudança recomendada:

1. substituir `OpenApiOAuthFlows.Implicit` por `AuthorizationCode`;
2. manter authorization e token URLs do discovery/issuer;
3. adicionar `OAuthUsePkce()` na Swagger UI;
4. manter o cliente público e sem secret;
5. adicionar ao cadastro `authorization`, `token`, `authorization_code`, response type `code` e requirement PKCE;
6. remover refresh token/offline access, que não são necessários para uma sessão de Swagger;
7. manter apenas o redirect HTTPS público de produção;
8. usar outro client ID para localhost/Development;
9. autorizar no CORS do STS apenas a origem pública do EndPoints;
10. testar no browser a troca do code, uso do bearer token e logout/limpeza do token.

A base `identity2` copiou `SufficitEndPointsSwaggerUI` como público, mas deixou somente token endpoint, refresh grant e scope `policies`; faltam authorization endpoint, authorization code, response type code e PKCE. O registro atual não executa nem o fluxo antigo nem o novo no OpenIddict.

Como o volume é mínimo, o mesmo client ID pode receber code+PKCE no Duende antes do deploy e perder implicit logo após a validação. No OpenIddict ele deve existir apenas no formato final. Não há justificativa para habilitar implicit como feature flag no novo Server.

### 20.5 Admin UI e Admin API

O Admin UI atual já está no estado correto:

- client implantado: `skoruba_identity_admin`;
- response type code;
- PKCE habilitado;
- cliente confidencial;
- uso real observado.

Na base `identity2`, endpoints, grant, response type e requirement PKCE foram migrados corretamente, mas o client secret está ausente. É necessário gerar uma nova credencial, armazená-la fora de appsettings e configurar aplicação e OpenIddict de forma coordenada. Não se deve tentar reutilizar o hash do Duende como plaintext.

O Admin API usa Swagger/NSwag com authorization code + PKCE no código, mas há drift de client ID: a configuração de produção observada aponta para `sufficit_identity_admin_api_swaggerui`, enquanto os bancos contêm `skoruba_identity_admin_api_swaggerui`. Não houve tráfego recente desse Swagger. Deve-se escolher um ID canônico, alinhar código, Duende e OpenIddict e adicionar a origem HTTPS da Admin API ao CORS.

Os clientes antigos `skorubaserveradmin` e `SufficitIdentityAdminApi` não devem ser usados como evidência de que o Admin atual depende de hybrid/implicit. Eles devem entrar em quarentena, ser monitorados por pelo menos 30 dias e então desabilitados.

### 20.6 Provisionamento como código

O drift observado foi causado em parte por cadastros manuais e por uma conversão que descartou grants incompatíveis sem criar os grants finais. A solução permanente é um manifesto versionado, sem segredos, contendo:

- client ID, tipo e consent type;
- endpoints, grants, response types e requirements;
- scopes/resources;
- redirects, post-logout redirects e CORS por ambiente;
- token format e lifetimes aprovados;
- referência lógica do secret, nunca o valor.

Um provisionador idempotente deve aplicar o mesmo manifesto ao Duende durante a transição e ao OpenIddict no destino, produzir diff antes de escrever e falhar se encontrar cliente confidencial sem secret. Isso substitui alterações SQL manuais e evita que um client perca `authorization_code` silenciosamente.

### 20.7 Sequência de rollout

#### Onda 0 — conter exposição de credenciais

Durante esta reavaliação foram encontrados arquivos versionados com material de credencial em `sufficit-web` e `sufficit-endpoints`, incluindo uma chave privada e appsettings com secrets configurados. Nenhum valor foi copiado para este relatório.

Antes de mudar OAuth:

1. revogar/rotacionar todas as credenciais desses arquivos;
2. remover appsettings reais e chaves do Git;
3. reescrever o histórico dos repositórios afetados;
4. force-push coordenado e reclone dos workspaces/runners;
5. publicar somente templates com placeholders;
6. materializar os valores por GitHub Environments, vault ou credencial do host;
7. executar secret scan obrigatório na CI.

Não se deve considerar resolvido apenas porque o repositório de Identity teve seu histórico limpo; os achados estão nos repositórios consumidores.

#### Onda 1 — tornar a entrega controlável

- remover deploy automático de produção em push para `sufficit-web/main`;
- criar CI de build/test em PR e deploy somente manual com approval;
- reativar a CI de `sufficit-endpoints`, separando build de deploy;
- remover `continue-on-error` do deploy antigo;
- gerar um artefato único e promover o mesmo checksum aos nós;
- adicionar smoke test e rollback por destino.

Hoje um push em `sufficit-web/main` publica diretamente no nó Web primário, enquanto o único workflow de EndPoints está desabilitado. Alterar autenticação sob essas condições não é seguro.

#### Onda 2 — provisionar sem retirar compatibilidade

1. aplicar o manifesto no Duende atual;
2. criar `sufficit_web` com code+PKCE;
3. adicionar code+PKCE ao Swagger EndPoints;
4. alinhar os clients administrativos atuais;
5. aplicar o mesmo estado final em `identity2`;
6. gerar/armazenar os novos secrets dos clients confidenciais;
7. validar discovery, PAR, token e UserInfo sem tráfego de usuário.

O client WebForms antigo permanece intacto nessa onda. No Swagger, implicit pode coexistir apenas no Duende durante a curta janela entre cadastro e deploy; jamais no OpenIddict.

#### Onda 3 — WebForms canário

1. implementar code+PKCE e o novo contrato de UserInfo;
2. testar em IIS de homologação com o Duende atual;
3. publicar primeiro em um nó Web de standby;
4. testar diretamente esse backend com hostname/SNI correto;
5. validar login, diretivas, roles, logout, recycle e failover;
6. publicar no segundo standby;
7. publicar por último no nó primário;
8. monitorar autorizações por client ID, erros de callback e acesso negado por diretiva.

Rollback consiste em restaurar o artefato/config anterior no nó e voltar ao client `SufficitWebForms`, ainda ativo no Duende. Não requer habilitar hybrid no novo servidor porque esta onda acontece antes do cutover.

#### Onda 4 — Swagger e Admin

1. publicar EndPoints code+PKCE nos standbys e depois no primário;
2. validar a troca do code no browser e o token contra a API;
3. remover implicit de `SufficitEndPointsSwaggerUI` no Duende;
4. rotacionar o secret do Admin UI e preencher o OpenIddict;
5. corrigir o client ID do Swagger da Admin API;
6. validar Admin UI e Admin API sem depender de registros antigos.

#### Onda 5 — retirada e gate do novo STS

- observar pelo menos 7 dias sem hybrid/implicit para clients conhecidos;
- observar 30 dias antes de excluir registros administrativos/genéricos sem owner;
- desabilitar primeiro, remover depois;
- atualizar a fixture de produção para demonstrar aceitação dos novos requests e rejeição dos antigos;
- manter no discovery novo apenas `code`, sem `token`, `id_token` ou combinações híbridas;
- só então considerar R3 fechado no gate do cutover OpenIddict.

### 20.8 Testes de aceitação específicos

- WebForms inicia autorização com `response_type=code`, `code_challenge_method=S256`, nonce e state;
- token request contém verifier correto e o code não é reutilizável;
- nenhum code, access token, refresh token ou client secret aparece em logs;
- login WebForms sobrevive a recycle e failover entre os três nós;
- UserInfo retorna roles/diretivas somente com os scopes correspondentes;
- usuário sem diretiva continua bloqueado e usuário com diretiva mantém acesso;
- Swagger EndPoints envia code+PKCE e recebe token sem client secret;
- CORS aceita somente as origens produtivas cadastradas;
- Admin UI autentica com nova credencial e code+PKCE;
- Admin API Swagger usa o mesmo client ID existente no store;
- requests `response_type=token`, `code id_token` e PKCE `plain` permanecem rejeitados no novo STS;
- telemetry registra zero uso dos IDs antigos antes de desabilitá-los.

### 20.9 Conclusão desta reavaliação

Hybrid/implicit não precisa mais ser tratado como impedimento estrutural do novo servidor. É um trabalho de modernização dos consumidores, executável agora contra o issuer legado e com rollback independente.

O esforço principal está no WebForms, mas o middleware já possui as primitivas necessárias. A mudança deve corrigir também o resgate tardio de code, logging de token e cache local, não apenas trocar uma string de response type. O Swagger é uma alteração pequena. Admin já está majoritariamente moderno; seus problemas são drift de cadastro e secrets ausentes.

Após essas ondas, o OpenIddict pode permanecer estrito desde o primeiro dia, e R3 deixa de bloquear o cutover sem adicionar dívida de compatibilidade ao `Sufficit.Identity.Server`.
