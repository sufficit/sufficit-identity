# Avaliação independente do Sufficit Identity

**Data de corte:** 7 de agosto de 2026

**Modelo:** GPT-5

**Projeto avaliado:** Sufficit Identity 0.4.0-alpha
**Stack observado:** .NET 10, ASP.NET Core Identity, OpenIddict 7.6.0, EF Core/Pomelo, MySQL/MariaDB

## Resumo executivo

O projeto possui uma base OAuth/OIDC melhor do que a nota geral sugere: usa OpenIddict nos fluxos centrais, exige PKCE por padrão, remove o método plain, não habilita implicit/hybrid e mantém password/none desligados. Certificados persistentes são obrigatórios fora de Development, cookies são Secure, há sessões server-side revogáveis, consentimento e antiforgery, SCIM e gestão opt-in, passkeys, 2FA, testes extensos e build limpo.

O problema é o salto da base madura para protocolos e credenciais implementados ao redor dela. Há três pipelines divergentes de emissão de token, estado de segurança distribuído sem primitivas atômicas, controles de saída HTTP que não são usados e módulos cujas flags não removem suas rotas. Os bloqueadores mais graves são:

1. SSF/CAEP não isola streams por cliente e não aplica os filtros persistidos; um cliente com o escopo compartilhado pode ler, consumir ou desabilitar streams de terceiros e receber eventos de toda a base.
2. PAT permite converter qualquer access token local em credencial de até 365 dias e atribui todos os scopes configurados no ClaimScopeMap, sem scope próprio nem autenticação recente.
3. Token exchange estreita scopes, mas pode trocar a audiência/recurso para fora da delegação do subject token.
4. DPoP tem downgrade/replay e não é validado nas APIs protegidas pelo pipeline OpenIddict Validation.
5. CIBA, FAPI/mTLS, JAR/JARM e SSF são implementações próprias sem evidência de conformance e contêm falhas concretas.
6. Endpoints externos configuráveis são usados por HttpClient comum; a defesa SSRF existente não é ligada e sua conexão final está quebrada.
7. Mudanças de senha, passkey, MFA e identidade externa não compartilham uma política de step-up e revogação.
8. A gestão não tem isolamento de tenant por padrão; RoutePrefix e RequireAuthorization não correspondem às rotas e policies executáveis.
9. Vault desabilitado armazena segredos de forma reversível, e o script de instalação mistura certificado TLS e chave de assinatura, com fallback de senha fixa.

**Nota geral: 4,8/10.** Eu não recomendaria adotar o software hoje como STS geral de produção ou habilitar os protocolos avançados. Ele pode servir a um piloto controlado, single-tenant e de baixo risco, com SSF, CIBA, DPoP/FAPI, JAR/JARM, token exchange, DCR e PAT desligados ou isolados, enquanto os P0 deste relatório são implementados.

## Método e limites de evidência

A fonte de verdade desta avaliação foi exclusivamente o código executável, configuration binding, arquivos de projeto/lock, migrations, schema, composition root e testes. README, diretório docs, changelogs, planos e notas de design do próprio projeto não foram usados como evidência. Comentários no código também não foram aceitos como prova de comportamento; quando o executável contradiz um comentário, a divergência é registrada.

Foram inspecionados os 11 projetos, aproximadamente 57.057 linhas C# não geradas, componentes Razor/Blazor e assets que participam de autenticação, wiring, migrations não geradas, contratos e testes. Arquivos Designer e snapshots gerados foram tratados como confirmação de schema, não como desenho.

Verificações executadas:

- dotnet build da solução em Release com warnings como erro: 12 targets reportados pelo build, zero warnings e zero erros;
- dotnet test da solução em Release sem restore: 392 testes aprovados, zero falhas;
- 362 atributos Fact/Theory, 174 chamadas HTTP nos testes e 84 leituras estáticas de source;
- dotnet list package --vulnerable --include-transitive: nenhum advisory conhecido no feed consultado;
- dotnet list package --outdated --include-transitive: há atualizações pendentes;
- busca por SQL bruto: o código de aplicação usa EF/LINQ; não foi encontrada superfície de injeção SQL direta;
- inspeção do worktree e de configuração versionada: nenhum segredo runtime real foi identificado; credenciais encontradas são de teste/template.

Esses resultados não equivalem a pentest, conformance certification ou prova de ausência de vulnerabilidade. Em particular, vários testes arquiteturais leem o source como texto; eles protegem forma, não comportamento distribuído ou interoperabilidade.

## 1. Reconhecimento da arquitetura

### 1.1 Projetos e dependências

| Projeto | Responsabilidade observada | Dependências relevantes |
|---|---|---|
| Server | Composition root, middleware, rate limit, health, UIs e módulos opcionais | STS, Core, Management, SCIM, três projetos de UI |
| STS | Identity, OpenIddict, OAuth/OIDC e extensões próprias | Core, Vault, Application.Abstractions |
| Core | AppDbContext, entidades, mappings, migrations e lifecycle de conta | Identity EF, OpenIddict EF, Pomelo |
| Management | Controllers e casos de uso administrativos | Core, Vault, Application.Abstractions |
| Scim | Discovery, Users/Groups e provisionamento SCIM | Core |
| Vault | Envelope encryption e resolução de segredos | Core, Data Protection |
| Application.Abstractions | Contratos de conta, gestão, UI e segurança | sem EF/OpenIddict direto |
| UI / UI.Management / UI.Abstractions | Login, consentimento, conta, gestão e composição visual | contratos de aplicação |
| Tests | Testes unitários, integração HTTP e MariaDB | Server, SCIM e contratos |

Evidência principal: Sufficit.Identity.sln:10-38; src/server/Program.cs:109-164; arquivos csproj de cada projeto.

A melhor fronteira é a UI: ela depende de abstrações, e a Management UI reutiliza os mesmos serviços de aplicação que a API. A pior fronteira é Application.Abstractions: o csproj recompila arquivos físicos da árvore Management por Compile Include e símbolos condicionais, em vez de possuir seus contratos. Isso cria acoplamento físico inverso e risco de duas versões do mesmo arquivo. A correção é mover DTOs, interfaces, exceptions e capability names para arquivos reais de Application.Abstractions e fazer Management referenciá-los normalmente.

### 1.2 Fluxo de dados

~~~text
Browser / OAuth client / SCIM client
                |
                v
Server: forwarded headers, HTTPS/HSTS, headers, rate limit, authz
                |
       +--------+---------+----------------+
       |                  |                |
       v                  v                v
OpenIddict + STS     Public/Management UI   Management/SCIM APIs
       |                  |                |
       +-------- application services -----+
                          |
                          v
                    AppDbContext
                          |
                       MySQL

Estado auxiliar: IDistributedCache (memória local por padrão)
Saídas: RabbitMQ/SMTP, SSF push, logout backchannel, métricas, captcha/HIBP
~~~

No OAuth principal, OpenIddict valida request, cliente, grant, redirect URI e tokens; endpoints passthrough chegam a AuthorizationController; UserManager/SignInManager reidratam o usuário; o controller constrói principal, scopes, resources e destinations; SignIn devolve o principal ao pipeline OpenIddict, que emite e persiste os artefatos. Evidência: src/sts/ServiceCollectionExtensions.cs:371-864 e src/sts/Controllers/AuthorizationController.cs:104-861,1167-1343.

Essa sequência é sólida para authorization code, refresh, device e client credentials. PAT usa dispatcher/factory internos e grava metadata OpenIddict diretamente; CIBA gera JWT manualmente. A ausência de um kernel único de emissão explica divergências de claim, audience, lifetime, revogação e sender constraint.

### 1.3 Banco de dados

Um único AppDbContext agrega 25 tabelas de aplicação, além da tabela de histórico de migrations:

| Domínio | Tabelas |
|---|---|
| ASP.NET Identity | users, roles, userroles, userclaims, userlogins, usertokens, roleclaims |
| OpenIddict | applications, authorizations, scopes, tokens |
| Segurança | dataprotectionkeys, userpasskeys, oidcusersessions, vaultkeys |
| SCIM | scimuserprofiles, scimgroups, scimgroupusermembers, scimgroupgroupmembers |
| SSF | ssfstreams, ssfsetdeliveries |
| Operação | brandingthemes, managementauditevents, identitymetricsconfiguration, identityapplicationusageevents |

Evidência: src/core/Data/AppDbContext.cs:20-107,113-937 e nove migrations listadas em src/core/Data/IdentityDatabaseSchema.cs:20-34.

O contexto único simplifica transações, porém reúne credenciais, tokens, sessões, chaves, segredos, auditoria e dados de provisionamento sob a mesma conexão e cadeia de migrations. Isso aumenta blast radius, acopla módulos opcionais e impede privilégios de banco por domínio. Recomenda-se manter Identity+OpenIddict juntos inicialmente, mas extrair contextos operacionais para SCIM; Audit/Metrics/Branding; e Key/Security State, usando outbox para efeitos entre contextos.

Invariantes ausentes no modelo:

- BrandingTheme.IsActive possui índice não único;
- SsfSetDelivery.StreamId não tem FK e Jti não é único;
- ExternalId de perfis/grupos SCIM não é único;
- ValueComparer de string array compara sequência, mas calcula hash por referência.

Correção: colocar unicidade/FKs/check constraints no mapping e migrations, não apenas nos serviços. Evidência: src/core/Data/AppDbContext.cs:249-268,405-446,570-589,658-668.

### 1.4 Superfície HTTP

| Área | Endpoints observados |
|---|---|
| Metadata | /.well-known/openid-configuration, JWKS, /.well-known/oauth-protected-resource, /.well-known/ssf-configuration |
| OAuth/OIDC | /connect/authorize, /connect/token, /connect/userinfo, /connect/introspect, /connect/revocation, /connect/endsession, /connect/par |
| Device | /connect/deviceauthorization, /connect/device, /connect/device/info |
| Logout | /connect/logout, /connect/endsession, /connect/frontchannel-logout |
| Extensões | /bc-authorize, /connect/ciba/complete, /connect/ciba/token, /connect/register |
| Conta | /account/login/password, /account/passkeys/*, login externo e páginas Razor de registro/recuperação/2FA |
| PAT | /api/account/tokens e introspect local |
| SSF | /ssf/streams, /ssf/events |
| Gestão | /api/users, clients, scopes, claims, sessions, authorizations, audit, branding, database, metrics, provisioning, overview |
| SCIM | /scim/v2/users, groups, schemas, resource-types e service-provider-config |
| Operação | /health e /health/ready; Swagger apenas em Development |

Os endpoints nativos são configurados em src/sts/ServiceCollectionExtensions.cs:382-391. Controllers e atributos de rota confirmam os demais.

### 1.5 Grants, tokens e configuração

Habilitados globalmente: authorization_code, client_credentials, device_code, refresh_token e token exchange. Password e none são flags desligadas por padrão; implicit/hybrid não são habilitados. PKCE é exigido para todos por padrão e plain é removido. PAR existe e pode ser obrigatório globalmente; FAPI também exige PAR nos clientes perfilados.

Access tokens são reference tokens por padrão; refresh token lifetime é 14 dias; access token usa o default OpenIddict se não configurado. Scopes registrados incluem openid, email, profile, roles, offline_access, address, identity.management, sufficit_ai_openai_bridge e os configurados no ClaimScopeMap. Evidência: src/sts/ServiceCollectionExtensions.cs:466-475,527-531,579-647.

A superfície de configuração sob Sufficit:Identity cobre issuer, database/pool/watchdog, certificates, management, grants legados, PKCE, PAR, rate limit, distributed cache, lifetimes/formato, lockout, HSTS/CORS/CSP, captcha, senha, sign-in, 2FA, passkeys, claims, mTLS, logout, DPoP, FAPI2, JAR/JARM, SSF, CIBA e MCP/DCR. Vault usa Sufficit:Vault.

Fragilidades de configuração:

- Issuer e PublicUrl não são obrigatórios em produção;
- RequireShared e FailOnUntrustedProxy são false por padrão;
- CSP é Report-Only por padrão;
- RejectBreached é false;
- Vault é false e vira pass-through reversível;
- snapshots manuais de options convivem com rebind direto de IConfiguration;
- o ambiente é inferido diretamente de ASPNETCORE_ENVIRONMENT com comparação case-sensitive em STS;
- há duas classes ManagementOptions sobre a mesma seção.

Correção: OptionsBuilder com Bind, Validate, ValidateOnStart; um IPublicOriginProvider obrigatório; IHostEnvironment injetado; e validações cruzadas de topologia/feature. Apenas opções genuinamente dinâmicas devem usar IOptionsMonitor.

## 2. Controles positivos confirmados

- OpenIddict controla validação de redirect URI e permissões nos endpoints padrão.
- Authorization Code + PKCE S256 é o default; implicit/hybrid não aparece no server builder.
- ROPC/none, DCR, CIBA, DPoP, FAPI, JAR/JARM e SSF são opt-in.
- Password grant, quando ligado, usa CheckPasswordSignInAsync com lockout e resposta genérica.
- Confirmação de e-mail é exigida por padrão.
- Consentimento, logout POST, device approval, login e ceremonies de passkey usam antiforgery.
- Cookies são Secure fora de Development; HSTS, redirecionamento HTTPS e headers são aplicados.
- Certificados de signing e encryption são obrigatórios fora de Development no código da aplicação.
- Data Protection persiste no banco e pode ser protegido pelo certificado.
- Sessões web ficam server-side, enumeráveis e revogáveis.
- Desativar/excluir conta revoga tokens, authorizations e sessões via serviço central.
- SCIM é opt-in, sempre autenticado, e sua allowlist vazia falha fechada quando RequireAuthorization=true.
- CORS usa origens explícitas; Swagger é Development-only.
- Docker usa imagens por digest e usuário não root.
- Build e testes passam sem warnings; o audit NuGet não encontrou advisory conhecido.

Esses controles justificam preservar OpenIddict como núcleo, em vez de reescrever o protocolo inteiro.

## 3. Vulnerabilidades e riscos

Escala: Crítica = comprometimento amplo/sistêmico com pré-condição plausível; Alta = impacto grave ou quebra de boundary; Média = exploração mais condicionada, disponibilidade ou conformance; Baixa = hardening.

### V-01 — Crítica — SSF não isola streams por cliente

**Evidência.** SsfStreamsController exige somente um scope compartilhado e lista/lê/desabilita/verifica streams por ID. SsfPollController recebe qualquer stream_id. SsfStreamStore não persiste owner client/presenter. Arquivos: src/sts/Controllers/SsfStreamsController.cs:47-49,96-165; src/sts/Controllers/SsfPollController.cs:15-56; src/sts/SharedSignals/SsfStreamStore.cs:145-160,170-247.

**Exploração.** Com SSF Stream Management habilitado, um cliente que obtenha ssf_transmitter enumera streams de outro receiver, consome seus Security Event Tokens antes dele ou desabilita sua entrega. Em ambiente multi-tenant isso é BOLA com exfiltração e sabotagem.

**Solução.** Adicionar OwnerClientId/receiver subject ao schema; introduzir ISsfStreamAuthorizationPolicy e filtrar toda operação por presenter; separar scope administrativo de criação do credential/scope de polling de um stream. Migrar streams existentes e reprovisionar receivers. Trade-off: migration e mudança de clientes.

### V-02 — Crítica — filtros e verificação SSF são decorativos

**Evidência.** SubjectScope e EventsRequested são persistidos, mas SharedSignalsDispatcher envia cada evento a todo stream habilitado sem matcher. O endpoint verify gera state dentro do SET, não o persiste, e um POST subsequente marca o stream verificado sem conferir state; streams não ficam bloqueados antes da verificação. Arquivos: src/sts/SharedSignals/SsfStreamStore.cs:126-160; src/sts/SharedSignals/SharedSignalsDispatcher.cs:113-165; src/sts/Controllers/SsfStreamsController.cs:154-224.

**Exploração.** Um receiver cadastrado para um usuário ou tipo de evento recebe alterações de credencial/sessão de toda a base e consegue auto-verificar. Pull concorrente também pode consumir eventos indevidamente; Jti não é unique.

**Solução.** Criar ISsfSubscriptionMatcher sobre subject canônico e event type antes da geração/entrega; modelar lifecycle pending → challenge-issued → verified → disabled; persistir state com TTL/hash e comparação constante; entregar apenas SET de verificação enquanto pending. Usar outbox/lease transacional e unique (StreamId,Jti). Trade-off: normalização de subject e reprocessamento da fila.

### V-03 — Alta — PAT amplia lifetime e scopes

**Evidência.** PersonalTokensController requer qualquer bearer local, permite até 365 dias, copia claims não protocolares do caller e define todos os scopes presentes no ClaimScopeMap, não a interseção com scopes/resources do caller. Arquivo: src/sts/Controllers/PersonalTokensController.cs:25-41,153-272.

**Exploração.** Um access token curto e estreito roubado chama POST /api/account/tokens e vira PAT anual. Scopes/audiences derivados do mapa podem ampliar autorização; claims copiados ficam stale e nenhum step-up é exigido.

**Solução.** Remover emissão direta do controller e criar IPersonalTokenIssuancePolicy sobre o kernel único. Exigir scope personal_tokens.manage, MFA/recent auth, audience fixo, scopes explicitamente solicitados intersectados com caller e grants atuais, reidratar claims allowlisted e reduzir lifetime. Trade-off: automações existentes precisarão fluxo explícito de PAT/rotação.

### V-04 — Alta — token exchange amplia recurso fora da delegação

**Evidência.** Scopes são intersectados com o subject token, mas ResolveResourcesAsync recalcula resources a partir do novo request e não os intersecta com aud/oi_resrc original. Azp/presenter ausente passa; allowlist só é aplicada quando configurada. Arquivo: src/sts/Controllers/AuthorizationController.cs:739-861,1244-1260.

**Exploração.** Um actor autorizado a trocar tokens apresenta token de usuário destinado ao recurso A e solicita o mesmo scope para recurso B, ao qual o actor tem acesso. O STS emite token B sem o usuário ter delegado B.

**Solução.** Introduzir ITokenExchangePolicy com allowlist fechada, presenter obrigatório, tipos aceitos, may_act, interseção de target resource ou matriz explícita A→B, limite de cadeia/profundidade e audit. Trade-off: configuração explícita de relações de delegação.

### V-05 — Alta — DPoP pode ser ignorado nas APIs e reexecutado

**Evidência.** A validação de proof para consumo está registrada em AddServer, não no AddValidation usado por PAT, Management, SCIM e SSF. Um token cnf.jkt roubado pode ser apresentado como Bearer nessas APIs. No token endpoint, proof inválido vira null e só é fatal se RequireForAllClients/FAPI; um header inválido em modo opcional faz downgrade para bearer. O replay cache faz Get→Set→Get sem CAS, e memória local é o default. Arquivos: src/sts/Dpop/DpopTokenHandlers.cs:121-204; src/sts/ServiceCollectionExtensions.cs:597-603,860-864; src/sts/Controllers/AuthorizationController.cs:331-400; src/sts/Dpop/DistributedDpopReplayCache.cs:39-65.

**Exploração.** Token DPoP roubado é repetido contra /api ou /scim sem proof. Em emissão, um proxy/cliente altera um proof inválido e recebe bearer; duas réplicas podem aceitar o mesmo jti.

**Solução.** Extrair ISenderConstraintValidator protocol-neutral e executá-lo antes da authorization tanto no Server quanto no Validation. Header DPoP presente e inválido deve sempre falhar. Substituir IDistributedCache por IAtomicReplayStore.TryAddAsync com Redis SET NX ou índice único SQL e exigir backend atômico quando DPoP/FAPI estiver ligado. Trade-off: latência e dependência de estado compartilhado.

### V-06 — Alta — nonce DPoP global permite negação de serviço

**Evidência.** DistributedDpopNonceStore usa uma chave singleton; /connect/token emite/rotaciona antes de autenticar grant/cliente e gira diante de nonce ausente/inválido. Arquivos: src/sts/Dpop/DistributedDpopNonceStore.cs:15,48-73; src/sts/Controllers/AuthorizationController.cs:331-383.

**Exploração.** Um atacante anônimo mantém o nonce global rotacionando, invalidando proofs recém-gerados por clientes legítimos.

**Solução.** Nonce por client/key/transaction, com pequeno conjunto de graça e rotação somente após autenticação/proof estrutural plausível. Armazenar atomicamente. Trade-off: maior cardinalidade e retry mais complexo.

### V-07 — Alta — SSRF: a defesa existe, mas não protege nenhuma saída

**Evidência.** Os clients de métricas, captcha/HIBP, logout backchannel, SSF push e verificação usam AddHttpClient comum. AddSafeHttpClient tem zero consumidores. O callback seguro tentaria chamar ConnectCallback nulo de um novo SocketsHttpHandler. SSF aceita endpoint não vazio; logout aceita HTTPS; métricas aceita HTTP(S). Arquivos: src/sts/ServiceCollectionExtensions.cs:73-75,269,910-911,985-988,1017-1018; src/sts/SafeHttpHandlerFactory.cs:20-60; src/sts/SharedSignals/SsfStreamStore.cs:126-151; src/sts/Logout/BackchannelLogoutDistributor.cs:172-209; src/management/Metrics/MetricsManagementService.cs:238-251.

**Exploração.** Operador/cliente cria stream ou metadata para localhost, cloud metadata ou endereço interno; o STS faz POST com Authorization/SET ou é usado para mapear a rede. DNS rebinding evita validação apenas na entrada.

**Solução.** IOutboundHttpPolicy único e typed clients obrigatórios. Validar scheme/port, resolver uma vez, rejeitar private/link-local/ULA/mapped/reserved e conectar ao IP validado por Socket.ConnectAsync; desabilitar redirects; aplicar egress firewall. Criar allowlist separada para RPs internos. Trade-off: endpoints privados exigem declaração operacional.

### V-08 — Alta — CIBA é um protocolo paralelo, permissivo e não atômico

**Evidência.** /bc-authorize aceita qualquer cliente público registrado sem autenticação e não exige permissão CIBA. A aprovação depende de um POST que, ao desafiar login, constrói redirect para a própria rota POST; binding_message é persistido, mas não há UI que o apresente. Poll ocorre em /connect/ciba/token, não no token endpoint padrão; emite JWT manual com aud=client_id, enquanto resposta/row hardcode uma hora e o JWT usa lifetime configurado. TryConsumeApproved usa Get/Set sem CAS. O controller continua roteável quando CIBA está off, mas o generator só é registrado quando on. Arquivos: src/sts/Controllers/CibaController.cs:73-159,169-247,261-419; src/sts/Ciba/DistributedCibaPendingRequestStore.cs:98-130; src/sts/Ciba/CibaAccessTokenGenerator.cs:70-127; src/sts/ServiceCollectionExtensions.cs:1031-1057.

**Exploração.** Cliente público não autorizado provoca approval fatigue; polls concorrentes em réplicas emitem dois JWTs; revogar a row não invalida JWT offline; com feature desligada, probing pode gerar 500.

**Solução.** ICibaClientPolicy confidential-only com autenticação forte e permissão explícita; state machine persistente e consume atômico; approval UI que mostra binding message; emissão pelo ITokenIssuanceService/OpenIddict custom grant, com resources, lifetime, token format e sender constraint uniformes. Mapear controller apenas quando habilitado. Trade-off: reprovisionar clientes e desenvolver extensão/conformance real ou remover CIBA até upstream suportar.

### V-09 — Alta — mTLS/FAPI é anunciado sem autenticação e binding comprováveis

**Evidência.** Ativar mTLS registra aliases e metadata tls_client_certificate_bound_access_tokens=true; Program apenas escreve warning. Fapi2Policy considera qualquer Connection.ClientCertificate autenticação forte, sem provar que o certificado foi validado e vinculado ao cliente. Não há emissão observável de cnf.x5t#S256 nesse código. Arquivos: src/sts/ServiceCollectionExtensions.cs:404-422,761-768; src/server/Program.cs:368-393; src/sts/Fapi/Fapi2Handlers.cs:33-65,198-215.

**Exploração.** Client secret comum mais qualquer certificado aceito/encaminhado pelo host satisfaz o perfil custom; o token continua bearer embora discovery prometa sender constraint.

**Solução.** IClientAuthenticationAssurance alimentado pelo método efetivamente validado; enrollment e binding de certificado por aplicação; APIs nativas OpenIddict de mTLS/certificate-bound token; contrato verificável com proxy confiável. Mtls.Enabled sem IMtlsDeploymentAttestation deve falhar no startup, não avisar. Trade-off: operação de PKI e rotação por cliente. Não anunciar FAPI antes de suite oficial de conformance.

### V-10 — Alta — claims custom são liberados por default

**Evidência.** BuildIdentityAsync copia todos os AspNetUserClaims não reservados. GetDestinations envia claims mapeados apenas com scope, mas qualquer tipo ausente do mapa vai ao access token. O mapa default cobre somente directive. Arquivos: src/sts/Controllers/AuthorizationController.cs:1167-1230,1274-1343; src/sts/SufficitIdentityOptions.cs:697-715.

**Exploração.** Uma integração grava PII ou claim de autorização interno sem atualizar o mapa; qualquer cliente que receba access token para o usuário obtém o valor.

**Solução.** IClaimReleasePolicy deny-by-default considerando claim, client, scopes, resource, grant e token destination; separar claims internos, de autorização e de profile; executar shadow audit antes do corte. A mesma policy deve atender OAuth, PAT e CIBA. Trade-off: consumidores de claims implícitos precisarão declarar contrato.

### V-11 — Alta — mudanças de credencial não revogam artefatos existentes

**Evidência.** Reset público só chama ResetPasswordAsync; self change atualiza/refresh do cookie atual; reset administrativo também não chama o revoker central. IdentityAccountLifecycleService já consegue revogar tokens, authorizations e browser sessions, mas só é usado para active/delete. Arquivos: src/sts/AspNetCoreIdentityAccountOnboardingService.cs:244-283; src/sts/AccountSelfService.cs:50-107; src/management/Users/UserManagementService.cs:900-1016; src/core/Services/IdentityAccountLifecycleService.cs:13-63.

**Exploração.** Refresh token ou PAT roubado continua válido depois de a vítima redefinir a senha. O refresh reconsulta o usuário, mas a conta continua habilitada.

**Solução.** ICredentialMutationCoordinator: mutação, security stamp, revogação de OAuth tokens/authorizations/sessões e publicação de evento numa unidade coordenada; política opcional para preservar somente a sessão atual. Aplicar a senha, MFA, passkey e external login. Trade-off: logout/reconsent em dispositivos.

### V-12 — Alta — não há step-up/recent-auth para persistência de conta

**Evidência.** Adicionar/remover passkey, regenerar recovery codes, resetar/desligar MFA e ligar/remover IdP externo aceitam sessão cookie+antiforgery, sem senha, TOTP, passkey ou auth_time recente. Arquivos: src/sts/Controllers/AccountPasskeysController.cs:23-68; src/sts/AspNetCoreIdentityPasskeyService.cs:72-183,247-299; src/sts/AspNetCoreIdentityAccountTwoFactorService.cs:181-298; src/sts/AspNetCoreIdentityAccountExternalIdentityService.cs:70-214.

**Exploração.** Sessão roubada ou XSS registra passkey do atacante, regenera códigos, desliga MFA ou vincula IdP para acesso persistente.

**Solução.** IStepUpAuthorizationService na boundary de aplicação, com AAL, auth_time máximo e transaction id; controllers/UI apenas iniciam o challenge. Ao concluir, rotacionar a sessão e chamar ICredentialMutationCoordinator. Trade-off: prompt adicional e fluxo explícito de recovery.

### V-13 — Alta condicional — links de recuperação dependem de Host

**Evidência.** Se PublicUrl estiver ausente, BuildAbsolute usa Request.Scheme e Request.Host em links de reset/confirmação. Issuer também é opcional, e PAT deriva issuer do request como fallback. Arquivos: src/sts/AspNetCoreIdentityAccountOnboardingService.cs:160-174,286-305,325-339; src/sts/ServiceCollectionExtensions.cs:425-444; src/sts/Controllers/PersonalTokensController.cs:611-619.

**Exploração.** Em deployment com AllowedHosts/proxy permissivo, atacante solicita reset da vítima enviando Host malicioso; o e-mail contém token válido apontando ao atacante, que captura o query string e o usa no host real.

**Solução.** IPublicOriginProvider com URI HTTPS imutável obrigatória fora de Development, usada por issuer, e-mail, aliases e metadata. Nunca construir URL de segurança do request. Multi-tenant deve mapear tenant→origin explicitamente. Trade-off: configuração obrigatória e lista de origins.

### V-14 — Alta/Média — Vault e transporte de segredos falham abertos

**Evidência.** Vault é desligado por padrão e PassThroughKeyVault apenas base64url-prefixa plaintext. VaultBackedClientSecretResolver, mesmo com Vault ligado, captura FormatException e retorna a referência original. Segredos SSF/métricas podem assim ficar reversíveis no banco. Arquivos: src/vault/ServiceCollectionExtensions.cs:22-41; src/vault/PassThroughKeyVault.cs:14-43; src/vault/VaultBackedClientSecretResolver.cs:47-58.

**Exploração.** Dump do banco revela Authorization de receiver, segredo de métricas ou secret provisionado; erro de formato silenciosamente rebaixa para plaintext.

**Solução.** ISecretProtector estrito: plaintext apenas em uma implementação Development separada; em produção, formato inválido falha fechado. Validar no startup qualquer feature que persista segredo, migrar/recriptografar rows e usar KMS/HSM/KEK próprio. Trade-off: migração e dependência de key service.

### V-15 — Alta operacional — lifecycle de signing keys e pacote systemd inseguros

**Evidência.** prestart.sh copia um PFX Let's Encrypt como signing cert ou gera self-signed em qualquer ambiente com senha fixa TestCerts2026. Depois executa chown -R do release para o usuário do serviço. O unit systemd não aplica ProtectSystem, NoNewPrivileges ou outras restrições. A mesma credential auxilia JARM, SSF, logout, CIBA e protege Data Protection. Arquivos: helpers/prestart.sh:19-58; helpers/sufficit-identity.service:8-35; src/sts/ServiceCollectionExtensions.cs:114-120,210-221,954-1056.

**Exploração.** Compromisso do processo permite modificar binários/scripts para persistência; rotação TLS substitui chave de token sem overlap de JWKS; fallback previsível inicia produção com chave fraca/inesperada.

**Solução.** IProtocolKeyRing com slots por finalidade, active+retiring keys, kid e publicação overlap; provider HSM/KMS para signing. Data Protection usa KEK próprio. Operacionalmente: release root-owned/read-only, apenas state dirs graváveis, remover fallback em produção e endurecer systemd. Trade-off: maior operação de chaves; é indispensável para HA/rotação.

### V-16 — Alta operacional — reset token pode trafegar sem TLS

**Evidência.** RabbitMQEmailQueue inclui link bearer no HTML. ConnectionFactory recebe host/user/password, mas não habilita SSL; SMTP aceita TLS desligado sem guard de produção. Arquivos: src/sts/Email/RabbitMQEmailQueue.cs:75-84; src/sts/Email/RabbitMqEmailPublisher.cs:125-144; src/sts/Email/DefaultEmailSenders.cs.

**Exploração.** Observador da rede/broker captura link de reset e toma a conta.

**Solução.** ISecurityMessageTransport com validation-on-start: AMQPS/mTLS/CA ou envelope encryption ao consumidor; SMTP exige StartTLS/SMTPS fora de Development. Certificados e ACLs são operacionais, mas o fail-fast é responsabilidade do software.

### V-17 — Média — JAR permite replay prolongado

**Evidência.** TokenValidationParameters valida lifetime, mas o max age só roda se iat existir e mede now−iat; não exige iat, jti ou typ, não limita exp−iat/exp−now e não guarda jti. Claims repetidos/arrays são reduzidos por enumeração de Claim; o texto próximo menciona jwks_uri fallback, mas ResolveSigningKeysAsync só lê JWKS embutido. Arquivo: src/sts/Jar/JarRequestObjectHandler.cs:178-278.

**Exploração.** Request object assinado sem iat e com exp distante é repetido até exp; parâmetros multivalorados podem mudar de semântica.

**Solução.** IRequestObjectValidator: exigir typ, iat, exp, jti; limitar lifetime/freshness; IAtomicReplayStore por client+jti; preservar JsonElement/arrays; resolver keys por metadata com política SSRF se jwks_uri for suportado. Trade-off: clientes antigos precisam corrigir request objects.

### V-18 — Média/Alta — JARM usa chave de encryption global do servidor

**Evidência.** JarmResponseGenerator recebe uma EncryptingCredentials singleton carregada de PFX global; não resolve chave pública/algoritmos do cliente. Arquivos: src/sts/ServiceCollectionExtensions.cs:954-978; src/sts/Jarm/JarmResponseGenerator.cs:19-96.

**Exploração.** Todos os clients dependeriam da mesma chave privada/global; clientes comuns não conseguem decriptar sua resposta, e o AS retém material privado que deveria pertencer ao receiver.

**Solução.** IJarmClientKeyResolver sobre application metadata, usando somente public key do cliente e seus alg/enc permitidos; rotação por client e conformance tests. Trade-off: cadastro JWKS obrigatório.

### V-19 — Média — gestão é BOLA por default e sua configuração não funciona

**Evidência.** DefaultManagementObjectAccessPolicy permite todo objeto; o adapter do host dá todas as capabilities ao role administrator. RoutePrefix só controla MapWhen, mas controllers fixam api/* e Program já chama MapControllers. RequireAuthorization=false deixa de registrar policy, enquanto os controllers continuam a exigi-la. Arquivos: src/management/Authorization/ManagementAuthorization.cs:397-417; src/server/Management/SufficitOperatorManagementEntitlementResolver.cs:13-37; src/management/ServiceCollectionExtensions.cs:109-138,208-225; src/server/Program.cs:536-553.

**Exploração.** Em ambiente multi-tenant, qualquer administrator gerenciado age sobre todos os usuários/clientes. Alterar prefixo não move rota; desligar authorization tende a 500 por policy ausente.

**Solução.** IManagementObjectAccessPolicy tenant-aware obrigatório fora de single-tenant; separar workforce operator role de roles emitidas a clientes. Mapear um RouteGroupBuilder uma única vez, com prefixo real; registrar sempre policy e remover bypass anônimo. Trade-off: tenant id/context deve entrar nos resources e queries.

### V-20 — Média — evidência MFA não chega aos tokens

**Evidência.** O principal de sessão adiciona sid e aal, mas BuildIdentityAsync do token projeta sub/email/name/roles/claims e sid, não amr/acr/auth_time. Management/SCIM exigem amr em suas policies. Arquivos: src/sts/OidcSessionClaimsPrincipalFactory.cs:30-63; src/sts/Controllers/AuthorizationController.cs:1167-1192; src/management/Authorization/ManagementAuthorization.cs:500-533.

**Impacto.** Login 2FA real pode produzir token sem amr, negando gestão e incentivando o operador a desligar RequireMfa; testes que montam amr manualmente não provam o fluxo real.

**Solução.** IAuthenticationContextProjector que grava amr/acr/auth_time por sessão no término de cada fator e os projeta em authorization code/token. Não persistir isso como user claim. Policies de alto risco devem exigir AAL e max age.

### V-21 — Média — passkeys são bloqueadas pelo próprio header

**Evidência.** Permissions-Policy define publickey-credentials-get=() para toda resposta, enquanto a UI usa navigator.credentials.get/create. Arquivo: src/sts/SecurityHeadersMiddlewareExtensions.cs:26-31,66-80 e componentes de passkey.

**Impacto.** Navegadores que aplicam a policy recusam WebAuthn no próprio origin; testes source/HTTP não exercitam browser.

**Solução.** ISecurityHeaderPolicy por surface/route, permitindo publickey-credentials-get=(self) onde necessário; testes Playwright/WebDriver de registro e login. Trade-off mínimo.

### V-22 — Média — rate limiting é apenas por IP e local

**Evidência.** Fixed-window por RemoteIpAddress cobre POST sensíveis; proxy não configurado só falha se flag opt-in. Username inexistente no password grant evita hash real; login UI distingue estados internos em seu fluxo. Arquivos: src/server/Program.cs:190-267,319-337; src/sts/Controllers/AuthorizationController.cs:696-721; src/sts/Controllers/PasswordLoginController.cs:20-60.

**Exploração.** Botnet faz password spraying; NAT compartilha bucket e sofre DoS; diferenças de timing/status ajudam enumeração.

**Solução.** IAbuseProtectionService distribuído com partitions por endpoint, client, HMAC(account) e IP, progressive delay/dummy hash/risk signals; WAF no edge. Trade-off: tuning e falsos positivos.

### V-23 — Média — SCIM não audita as negações que pretende

**Evidência.** ScimAuthorizationAuditFilter é IAsyncActionFilter. Falha de Authorize encerra antes da action, logo o filtro não executa em 401/403 de authorization. Arquivos: src/scim/ScimAuthorizationAuditFilter.cs:16-64; src/scim/ScimControllers.cs:71-75,169-173.

**Solução.** IAuthorizationMiddlewareResultHandler ou handler de policy publica evento por outbox. Separar ScimProvisioningService, hoje com 1.586 linhas, em user/group service, filter parser, patch applicator, repository e publisher. Trade-off: mais componentes, testes muito mais focados.

### V-24 — Média — DCR tem lifecycle e validação incompletos

**Evidência.** DCR usa token inicial estático, aceita client_id/secret escolhidos pelo caller e não implementa read/update/delete/rotation. URI de loopback aceita qualquer scheme porque somente non-loopback é forçado a HTTPS. Arquivo: src/sts/Controllers/RegistrationController.cs:39-185.

**Exploração.** Vazamento do initial token permite registros ilimitados; ftp://localhost ou outro scheme passa a regra local; secret fraco escolhido pelo caller vira client credential.

**Solução.** IDynamicClientRegistrationService com access tokens curtos/single-use/audit, client_id/secret gerados pelo servidor, metadata validation canônica e lifecycle protegido. Para MCP, preferir CIMD/metadata explícita quando aplicável. Trade-off: maior estado e incompatibilidade com callers atuais.

### V-25 — Média — sessão server-side acopla autenticação ao banco

**Evidência.** OidcUserSessionTicketStore consulta banco em toda request cookie, ignora cancellation com CancellationToken.None e toca LastActivity periodicamente. Arquivo: src/sts/OidcUserSessionTicketStore.cs:68-159.

**Impacto.** Falha/latência MySQL derruba login e UI; escrita de atividade aumenta contenção. O benefício é revogação forte.

**Solução.** ISessionTicketRepository com cache read-through curto e invalidação/revocation version; honrar cancellation; batch/async activity updates. Manter DB como source of truth. Trade-off: janela curta de revogação e cache compartilhado.

### V-26 — Média — migrations rodam no processo web

**Evidência.** Program executa MigrateAsync no startup quando configurado. Arquivo: src/server/Program.cs:469-496.

**Impacto.** Réplicas concorrem, startup fica acoplado a DDL e identidade web recebe privilégio de schema.

**Solução.** Migrator/job separado com advisory lock e credencial DDL; host usa IDatabaseSchemaReadiness apenas para compatibilidade/readiness. Trade-off: etapa adicional de deployment.

### Dependências

O audit NuGet não encontrou CVE conhecido em 07/08/2026. Isso não cobre falhas lógicas acima nem garante feed completo. Atualizações relevantes observadas: Swashbuckle 7.2.0→10.2.3; RabbitMQ.Client 7.2.1→7.2.2; QRCoder 1.6.0→1.8.0; IdentityModel transitivo 8.19.2→8.22.0; MySqlConnector 2.5.0→2.6.1. O fork local Pomelo 10.0.0 torna provenance/SBOM e processo de atualização especialmente importantes.

Recomendação: Renovate/Dependabot com lockfiles, SBOM assinado, provenance do nupkg local, scan em cada PR e janela mensal de atualização. Não há justificativa para classificar uma versão apenas como vulnerável sem advisory; o finding é governança/staleness.

## 4. Discrepâncias entre alegações próximas e código

Sem usar comentários como verdade, encontrei afirmações próximas ao código que o executável contradiz:

- DistributedDpopReplayCache se descreve atômico, mas usa Get/Set/Get sem CAS.
- ScimAuthorizationAuditFilter afirma observar falhas de authorization, mas action filters não rodam nesse short-circuit.
- SafeHttpHandlerFactory afirma proteger saídas; nenhuma saída o usa e sua conexão final dereferencia callback nulo.
- CIBA é descrito como condicionado à flag; o controller sempre integra o application part.
- JAR menciona exp bounded e fallback jwks_uri; o código não exige iat/jti nem busca URI.
- Management RoutePrefix/RequireAuthorization aparecem como surface configurável, mas atributos/policy fixos impedem esses efeitos.
- ProtectedResourceMetadataEnabled existe, mas o controller não consulta a flag.

Essas divergências são também um problema de qualidade: testes devem verificar o comportamento alegado, não strings no source.

## 5. Mercado e baseline moderno em 2026

Esta seção é a única que usa documentação pública externa. Versões e capacidades são o estado observado em 07/08/2026; ND significa não documentado nas fontes oficiais consultadas, não prova absoluta de inexistência.

### 5.1 Produtos

| Produto | Versão/entrega observada | Licença | Arquitetura/posição |
|---|---|---|---|
| Keycloak | 26.7.1, 05/08/2026 | Apache-2.0; suporte Red Hat disponível | IdP/STS turnkey Java/Quarkus, multi-realm, relacional e cluster |
| Duende IdentityServer | 8.0.3 | source-available; licença comercial em produção, Community para elegíveis | framework ASP.NET Core; host compõe UI/stores; módulos pagos |
| OpenIddict | 7.6.0 | Apache-2.0 | toolkit .NET modular; deliberadamente não é IdP pronto |
| ZITADEL | 4.16.2 | AGPL-3.0 desde v3 ou comercial | Go all-in-one/stateless, PostgreSQL, event sourcing/CQRS, multi-tenant |
| Ory Hydra + Kratos | 26.2.0 | core Apache-2.0; cloud/OEL comerciais | OAuth headless separado de identidade/login; composável, mais operacional |
| authentik | 2026.5.6 | core MIT; enterprise separado | IdP turnkey, PostgreSQL/workers/outposts, forte em SSO/federação |
| Authelia | 4.39.20 | Apache-2.0 | companion de reverse proxy; OIDC Provider ainda open beta |
| Auth0 | SaaS contínuo | proprietário | CIAM gerenciado; Actions, Organizations, FGA e oferta MCP/agentes |
| Okta Identity Engine | SaaS contínuo | proprietário | workforce/CIAM, risk/policy/provisioning e identidades de agentes |
| Microsoft Entra ID | SaaS contínuo | proprietário | workforce/cloud IAM, Conditional Access, CAE, workloads e Agent ID |
| node-oidc-provider | 9.11.2 | MIT | biblioteca Node orientada à conformance, referência embutível |

Fontes: [Keycloak release 26.7.1](https://github.com/keycloak/keycloak/releases/tag/26.7.1), [Duende NuGet](https://www.nuget.org/packages/Duende.IdentityServer), [OpenIddict 7.6](https://github.com/openiddict/openiddict-core/releases/tag/7.6.0), [ZITADEL release](https://github.com/zitadel/zitadel/releases/tag/v4.16.2), [ZITADEL architecture](https://zitadel.com/docs/concepts/architecture/software), [ZITADEL licensing](https://help.zitadel.com/zitadel-licensing-faqs), [Ory Hydra](https://github.com/ory/hydra), [authentik release](https://github.com/goauthentik/authentik/releases/tag/version/2026.5.6), [authentik license](https://github.com/goauthentik/authentik/blob/main/LICENSE), [Authelia release](https://github.com/authelia/authelia/releases/tag/v4.39.20), [node-oidc-provider](https://github.com/panva/node-oidc-provider/blob/main/CHANGELOG.md).

### 5.2 Protocolos e postura

| Produto | Passkeys | OAuth 2.1/BCP | FAPI 2 | DPoP | RFC 8693 | SSF/CAEP | AI/MCP |
|---|---:|---:|---:|---:|---:|---:|---:|
| Sufficit Identity | código existe, header bloqueia | boa base | custom inseguro | custom inseguro | custom inseguro | custom crítico | PRM/DCR parcial |
| Keycloak | sim, opt-in | perfis modernos | sim, final | sim | parcial | transmissor experimental | MCP/CIMD parcial |
| Duende 8 | módulo | sim | sim | sim | sim | ND | primitives, sem MCP nativo documentado |
| OpenIddict 7.6 | externo | primitives | ND | ND | sim | ND | PRM em roadmap 8 |
| ZITADEL | sim | parcial; implicit ainda existe | ND | ND | sim | ND | padrões para agentes |
| Ory | via Kratos | Hydra se posiciona 2.1 | ND | ND | parcial | ND | device/agentic, MCP ND |
| authentik | sim | PKCE, mas implicit/hybrid | ND | ND | ND | ND | ND |
| Authelia | WebAuthn | bom subset | parcial | não | não | não | RFC 9728 não |
| Auth0 | sim | sim | sim | sim | sim/OBO | ND | MCP, token vault, HITL |
| Okta | sim | sim | componentes | sim | sim para agentes | sim | MCP, actor chains, ID-JAG |
| Entra | sim | code+PKCE | ND | usa PoP próprio, não RFC 9449 | OBO/FIC, não grant genérico | CAE/CAEP | Agent ID |

Fontes oficiais: [Keycloak specifications](https://www.keycloak.org/securing-apps/specifications), [Keycloak client profiles/FAPI](https://www.keycloak.org/securing-apps/oidc-layers), [Keycloak SSF](https://www.keycloak.org/securing-apps/ssf-support), [Keycloak MCP](https://www.keycloak.org/securing-apps/mcp-authz-server), [Duende specs](https://docs.duendesoftware.com/identityserver/overview/specs/), [Duende FAPI 2](https://docs.duendesoftware.com/identityserver/tokens/fapi-2-0-specification/), [Duende passkeys](https://docs.duendesoftware.com/identityserver/usermanagement/authentication/passkeys/), [Duende licensing](https://docs.duendesoftware.com/general/licensing/), [OpenIddict architecture](https://documentation.openiddict.com/introduction), [OpenIddict token exchange migration](https://documentation.openiddict.com/guides/migration/60-to-70), [OpenIddict PAR](https://documentation.openiddict.com/configuration/pushed-authorization-requests), [OpenIddict PKCE](https://documentation.openiddict.com/configuration/proof-key-for-code-exchange), [OpenIddict mTLS](https://documentation.openiddict.com/configuration/mutual-tls-authentication), [ZITADEL token exchange](https://zitadel.com/docs/guides/integrate/token-exchange), [ZITADEL grants](https://zitadel.com/docs/apis/openidoauth/grant-types), [Ory releases](https://github.com/ory/hydra/releases), [authentik OAuth](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/), [authentik WebAuthn](https://docs.goauthentik.io/add-secure-apps/flows-stages/stages/authenticator_webauthn/), [Authelia OIDC matrix](https://www.authelia.com/integration/openid-connect/introduction/).

Para SaaS: [Auth0 brute-force](https://auth0.com/docs/secure/attack-protection/brute-force-protection), [Auth0 OBO](https://auth0.com/docs/secure/call-apis-on-users-behalf/on-behalf-of-token-exchange), [Auth0 MCP](https://auth0.com/ai/docs/mcp/intro/why-auth-for-mcp), [Okta DPoP](https://developer.okta.com/docs/guides/dpop/nonoktaresourceserver/main/), [Okta SSF](https://developer.okta.com/docs/reference/ssf-transmitter-sets/), [Okta agent token exchange](https://developer.okta.com/docs/guides/ai-agent-token-exchange/secret/main/), [Entra CAE](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation), [Entra PoP](https://learn.microsoft.com/en-us/entra/msal/dotnet/advanced/proof-of-possession-tokens), [Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/agent-oauth-protocols).

### 5.3 O baseline moderno

OAuth 2.1 ainda é draft, atualmente [draft-ietf-oauth-v2-1-15](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/). Uma alegação concreta de baseline deve significar code+PKCE S256 para clientes públicos/confidenciais, redirect URI exato, ausência de implicit/ROPC, refresh rotation/reuse control ou sender constraint, metadata RFC 8414, TLS e [OAuth Security BCP RFC 9700](https://datatracker.ietf.org/doc/rfc9700/).

Para alto risco, [FAPI 2.0 Security Profile final](https://openid.net/specs/fapi-security-profile-2_0-final.html) exige PAR, autenticação assimétrica, token sender-constrained, algoritmos estreitos e conformance demonstrada. Implementar handlers parecidos não equivale a FAPI certification.

DPoP RFC 9449 e token exchange RFC 8693 já são diferenciais práticos para microserviços/agentes. DPoP precisa ser enforced no resource boundary; exchange precisa preservar audience, scope e actor chain. SSF 1.0 é final ([especificação](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)), mas produção interoperável ainda é diferencial, não requisito universal.

MCP 2025-11-25 exige RFC 9728 Protected Resource Metadata e RFC 8414 AS Metadata; DCR é opcional ([MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)). Autorização de agentes madura acrescenta identidade própria do agente, sponsor, audience/resource binding, scopes granulares, actor chain, tokens curtos, exchange/OBO e human-in-the-loop.

O Sufficit atende parte da base OAuth 2.1, mas seus recursos avançados não devem ser contados como completos enquanto os findings e conformance não forem resolvidos.

### 5.4 Ranking

**Enterprise gerenciado:** Entra/Okta no topo para workforce/risk/lifecycle/CAE; Auth0 muito forte em CIAM/MCP/FAPI/DPoP; Keycloak gerenciado é a alternativa OSS mais ampla.

**Self-hosted turnkey:** Keycloak > ZITADEL > Ory Hydra/Kratos > authentik > Authelia, lembrando que Authelia tem escopo menor. O Sufficit fica abaixo dos quatro primeiros em maturidade e prontidão. Tem mais breadth nominal que Authelia, mas menor assurance nos protocolos próprios; breadth inseguro não melhora o ranking.

**Framework embutível:** Duende 8 > node-oidc-provider > OpenIddict 7.6 em completude pronta, embora licença, linguagem e finalidade sejam diferentes. A comparação justa do Sufficit é com uma aplicação endurecida sobre OpenIddict e com Duende. Ele acrescenta UI/gestão/SCIM/passkeys ao OpenIddict, mas hoje reduz a assurance da base ao implementar CIBA/DPoP/FAPI/SSF sem boundary/conformance suficiente.

## 6. Pontuação

| Dimensão | Nota | Justificativa objetiva |
|---|---:|---|
| Segurança | **3,5/10** | base OAuth segura, certificados/cookies/antiforgery bons; porém dois findings críticos SSF, PAT, exchange, DPoP, SSRF, credential lifecycle e secret/key management bloqueiam confiança |
| Arquitetura | **5,5/10** | projetos e UI/contracts razoáveis, managers OpenIddict e application services; mas três emissores, flags/rotas inconsistentes, cache sem semântica atômica, DbContext/SCIM monolíticos |
| Qualidade de código | **6,5/10** | nullable, build limpo, 392 testes, migrations testadas e boa legibilidade local; comments/testes de source divergem do executável e faltam testes browser, concorrência, feature-off e conformance |
| Completude de protocolo | **5,0/10** | amplo catálogo nominal, ótima base code/device/PAR; implementações custom avançadas são parciais, não standard endpoint ou inseguras, então não recebem crédito integral |
| Prontidão de produção | **3,5/10** | health/CI/container/sessões/audit existem; HA, atomicidade, key rotation, tenant isolation, egress, step-up e deployment systemd não estão prontos |
| **Geral** | **4,8/10** | média ponderada pelo risco: a base é recuperável, mas capabilities expostas excedem a maturidade dos boundaries |

Uma nota baixa aqui não pede reescrita total. O caminho de maior retorno é reduzir superfície e centralizar invariantes.

## 7. Architecture improvements

### P0 — antes de produção

1. **Kernel único de emissão.** Introduzir ITokenIssuanceService, TokenIssuanceRequest e profiles por grant em STS. Centralizar claim release, scopes/resources/audience, lifetime, sender constraint, format, persistência, revogação, audit e métricas. Migrar AuthorizationController, PersonalTokensController e CibaController; nenhum controller chama dispatcher interno ou grava token diretamente. Resultado esperado: elimina V-03, V-04, grande parte de V-08/V-10/V-18. Trade-off: refactor grande, mas preserva OpenIddict.

2. **Políticas explícitas deny-by-default.** IClaimReleasePolicy, ITokenExchangePolicy, IPersonalTokenIssuancePolicy e ICibaClientPolicy. As políticas recebem client/subject/grant/scopes/resources/auth context e retornam decisão auditável. Resultado: autorização deixa de emergir de ifs espalhados.

3. **Security state com semântica real.** Substituir IDistributedCache em DPoP/CIBA/SSF por ISecurityStateStore com TryAdd, TryConsume, CompareExchange, lease e capability flags Atomic/Shared. Redis SET NX/Lua ou SQL unique/transaction. Feature que exige atomicidade falha no startup se backend não suportar.

4. **Reconstruir ou desligar SSF.** Persistir owner, matcher e verification state; aplicar ISsfStreamAuthorizationPolicy e ISsfSubscriptionMatcher; outbox/lease e unicidade. Até isso estar entregue e testado, não expor /ssf e não anunciar SSF.

5. **Boundary de saída HTTP.** IOutboundHttpPolicy + typed clients e conexão IP-pinned, integrado a logout, SSF, metrics, captcha/HIBP. Egress firewall operacional. Nenhuma URL controlável pode usar IHttpClientFactory genérico.

6. **Credential security boundary.** ICredentialMutationCoordinator + IStepUpAuthorizationService + IAuthenticationContextProjector. Password/MFA/passkey/IdP passam por recent auth, stamp/revocation e amr/acr/auth_time de sessão. Resolve V-11, V-12 e V-20.

7. **Key e secret lifecycle.** IProtocolKeyRing com purpose separation e active/retiring; ISecretProtector fail-closed/KMS. Remover TLS cert como signing key, fallback self-signed de produção e ownership gravável do release.

### P1 — para arquitetura 7/10

8. **Módulos de protocolo como unidade.** IIdentityProtocolModule com AddServices, ConfigureOpenIddict, Validate e MapEndpoints. CIBA, SSF, DCR, PRM, JAR/JARM, DPoP/FAPI só registram services+routes+metadata juntos; off resulta 404. Adicionar suites feature on/off.

9. **Origin e options canônicos.** IPublicOriginProvider obrigatório, IHostEnvironment real e OptionsBuilder.ValidateOnStart. Uma classe ManagementOptions. Issuer/PublicUrl/proxy/cache/mTLS combinations validados.

10. **Gestão tenant-aware.** IManagementObjectAccessPolicy obrigatório, RouteGroupBuilder único e capability model separado de roles emitidas a usuários. Propagar tenant/context ao repository.

11. **Extrair contratos físicos.** Application.Abstractions passa a possuir interfaces/DTOs; remover Compile Include externo e #if dual-purpose. Teste arquitetural impede regressão.

12. **Decompor SCIM.** UserProvisioningService, GroupProvisioningService, IScimFilterParser, IScimPatchApplicator, repositories e event/audit publisher. Mover auditoria de denial para authorization pipeline.

### P2 — para arquitetura 8/10 e operação sustentável

13. **Bounded DbContexts e migrator.** Manter Identity+OpenIddict inicialmente; separar SCIM, audit/metrics/branding e security/key state; outbox para efeitos; migrations em job com advisory lock.

14. **Token format por client/resource.** ITokenFormatPolicy escolhe reference/JWT por consumer; evita tornar todo resource server dependente de introspection ou quebrar os que esperam JWT.

15. **Test strategy por risco.** Conformance OAuth/OIDC/FAPI/SSF; Playwright para passkeys/2FA/consent; testes concorrentes reais em Redis/MariaDB; feature-off 404; route prefix; host poisoning; DPoP no Validation; fault injection de DB/cache/key provider. Reduzir testes que apenas procuram strings.

16. **Observabilidade de segurança.** Eventos estruturados para issuance decision, exchange actor chain, PAT, step-up, replay, egress denial, key rotation e policy denial; métricas sem PII e audit outbox imutável.

Os itens 1–7 removem os blockers. Os itens 8–12 devem elevar a arquitetura para aproximadamente 7/10; os itens 13–16 são necessários para faixa 8/10.

## 8. Veredito

### Pontos fortes

O projeto escolheu uma fundação correta: OpenIddict e ASP.NET Core Identity, schema explícito, PKCE S256, grants legados off, reference tokens revogáveis, sessões server-side, UI por contratos, gestão com capability evaluator, SCIM opt-in, passkeys/2FA e CI funcional. Há mais engenharia real do que em um protótipo comum, e a suíte reduz risco de regressão nos fluxos já cobertos.

### Riscos que bloqueiam produção

- SSF cruza tenants/receivers e ignora subscriptions;
- PAT e exchange quebram least privilege;
- DPoP não é enforced em APIs e replay state não é atômico;
- CIBA/FAPI/JAR/JARM não têm assurance/conformance suficiente;
- saída HTTP permite SSRF;
- credential mutation não exige step-up nem revoga tudo;
- secret/key lifecycle e deployment systemd não sustentam rotação/compromisso;
- gestão, cache e banco assumem single-tenant/single-node em pontos críticos.

### Recomendação direta

**Não adotar hoje como STS geral de produção e não habilitar capabilities avançadas.** Para um piloto controlado, manter somente authorization code+PKCE, refresh, client credentials, device, endpoints OpenIddict padrão e UI básica; exigir issuer/public origin, Redis/atomic store quando houver mais de uma réplica, Vault/KMS, TLS nos transports e tenant policy explícita. Desligar SSF, CIBA, DPoP/FAPI custom, JAR/JARM, token exchange, DCR e PAT até seus gates estarem completos.

Para atingir arquitetura production-ready:

1. criar o kernel único de emissão e as policies deny-by-default;
2. substituir cache genérico por security state atômico;
3. reconstruir SSF e modularizar features/rotas;
4. criar outbound HTTP policy e credential mutation/step-up boundary;
5. implementar key/secret lifecycle com purpose separation;
6. aplicar tenant policy e origin/options fail-fast;
7. provar comportamento com conformance, browser e concurrency tests.

Se a necessidade é produção imediata, escolheria Keycloak/ZITADEL para self-hosted turnkey, Duende para framework .NET com suporte/conformance, ou Auth0/Okta/Entra conforme CIAM/workforce e restrições de SaaS. Se o objetivo estratégico é manter controle total em .NET e aceitar investimento, o Sufficit é uma base recuperável: preservar o núcleo OpenIddict e remover as implementações paralelas é o caminho mais curto, não uma reescrita.

## Apêndice A — evidência de build e dependências

- Solution version: 0.4.0-alpha; TargetFramework net10.0.
- OpenIddict 7.6.0; Microsoft/EF 10.0.10; Pomelo 10.0.0 local; RabbitMQ 7.2.1; Serilog 10; Swashbuckle 7.2; QRCoder 1.6.
- Build Release/warnaserror: sucesso, zero warnings/erros.
- Testes: 392/392.
- Audit NuGet: zero advisories conhecidos no feed consultado.
- Worktree antes da entrega: limpo; este relatório é a única alteração esperada.

## Apêndice B — arquivos-chave

- src/server/Program.cs
- src/sts/ServiceCollectionExtensions.cs
- src/sts/SufficitIdentityOptions.cs
- src/sts/Controllers/AuthorizationController.cs
- src/sts/Controllers/PersonalTokensController.cs
- src/sts/Controllers/CibaController.cs
- src/sts/Dpop/*
- src/sts/Fapi/*
- src/sts/Jar/* e src/sts/Jarm/*
- src/sts/SharedSignals/* e src/sts/Controllers/Ssf*
- src/sts/OidcUserSessionTicketStore.cs
- src/core/Data/AppDbContext.cs e src/core/Migrations/*
- src/core/Services/IdentityAccountLifecycleService.cs
- src/management/Authorization/ManagementAuthorization.cs
- src/scim/ScimProvisioningService.cs e ScimAuthorizationAuditFilter.cs
- src/vault/*
- helpers/prestart.sh e helpers/sufficit-identity.service
