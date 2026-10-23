# UserInfo e escopos sucessores

## Objetivo e estado inicial

Permitir que clientes com escopos sucessores autorizados recebam no UserInfo as mesmas claims liberadas pela política de emissão. O endpoint verificava apenas o escopo literal e descartava entitlements para um novo token exclusivo de uma API consumidora.

## Entrega

- Commit de código `f68eba975d79e6d05bac1c0332abc6938303861f`, sincronizado na main.
- AuthorizationController reutiliza IApplicationClaimPolicy também no UserInfo e no espelhamento de directive/entitlements. Não há regra de produto codificada nesse controlador.
- Claim temporária vinculada à identidade copiada, sem alterar o principal da requisição.
- Testes cobrem claims antigas/novas com escopo literal/sucessor e preservam a negativa sem escopo.
- Provisionamento administrativo registrado: escopo `orders.api`, único recurso `orders-api`; cliente existente recebeu `scp:orders.api`, `scp:personal.tokens.manage` e `ept:introspection`, preservando demais permissões.
- Nos três nós, drop-in `/etc/systemd/system/sufficit-identity.service.d/45-orders-api.conf` adiciona `orders.api` aos sucessores de directives (preservando entitlements) e `orders-api` aos ScopeClientIds de tokens pessoais (preservando `example-app`). MFA obrigatório e demais políticas existentes preservados.

## Validação e publicação

- `dotnet test src/tests/Sufficit.Identity.Tests.csproj -c Release --filter 'FullyQualifiedName~ClaimScopeMapTests|FullyQualifiedName~PersonalTokensTests|FullyQualifiedName~TokenIssuancePolicyTests'`: 52 aprovados.
- `dotnet build src/server/Sufficit.Identity.Server.csproj -c Release --no-restore --nologo -warnaserror`: 12 projetos, zero erros/avisos.
- Publicação coordenada, com trava por cluster/nó, staging e rollback: app-node-1, app-node-2 e app-node-3. Apenas STS.dll/PDB e REVISION foram atualizados. Demais assemblies, certificados, configurações e helpers preservados.
- STS SHA256: `43cbeb9e351eb012d19407955be3dae0febc5425cfa033a37ed9eb3099119115`.
- Backup por nó: `/opt/sufficit-identity.before-orders-api-20260910T204100Z`.
- Readiness, discovery/escopo orders.api, JWKS estável, rotas protegidas e assets verificados em todos os nós. Serviços ativos, sem reinícios automáticos.
- Autorização pública com o escopo `orders.api` e prompt=none aceita o contrato e responde login_required. Introspecção com o cliente da API autenticado responde active=false para token inválido.
- Uma tentativa inicial foi revertida automaticamente: o proprietário do certificado foi alterado por um chown recursivo no staging. A publicação final preserva conteúdo, proprietário, grupo e modo dos arquivos de configuração/certificados/helpers, verificados antes e depois.

## Limites

A emissão de um token de usuário real continua exigindo sessão interativa elegível, MFA e autenticação recente. Não se emitiu token em nome de usuário nem se contornou essa política no teste operacional. A integração do consumidor foi validada com issuer de teste e a política Identity com os testes acima.
