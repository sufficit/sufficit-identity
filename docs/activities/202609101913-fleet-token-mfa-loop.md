# Correção do loop de MFA na gerência de tokens do Fleet

Data: 2026-09-10, America/Sao_Paulo.

## Problema e reprodução

O Fleet chama seu `/account/reauthenticate` com retorno `/api-tokens`, `prompt=login` e `max_age=0`. O Identity verificava `agora - auth_time > max_age` também após concluir o TOTP. Com idade máxima zero e `auth_time` em segundos, até o login recém-concluído era recusado e iniciava outro MFA.

O teste HTTP integrado reproduziu o problema: TOTP válido seguido de redirect para `/account/reauthenticate` em vez do callback. Os testes anteriores usavam apenas `max_age=900`.

## Alterações

- Recibo de autenticação protegido por Data Protection, emitido somente pela continuação de um login de senha, autenticador ou código de recuperação bem-sucedido, com evidência de autenticação da requisição corrente.
- Vínculo com solicitação OIDC normalizada, sid e auth_time. Cookie Secure, HttpOnly, SameSite=Lax, prefixo __Host, validade máxima de cinco minutos. Não concede permissões e não substitui o cookie autenticado.
- Pedido novo com `max_age=0` exige nova cerimônia mesmo no mesmo segundo. Somente a continuação correspondente aceita o recibo. Pedidos sem max_age e com max_age positivo mantêm a política anterior.
- Campos técnicos de consentimento não mudam o vínculo; o recibo é mantido durante essa etapa e apagado quando o código é emitido. Alterações dos parâmetros OIDC não herdam a confirmação anterior.
- A renovação do security stamp preserva sid do ticket validado. Antes, a reconstrução do principal podia trocar sid antes de HttpContext.User ser preenchido, invalidando a identificação da sessão.
- Nenhuma alteração no Fleet, na política MFA dos tokens, nos escopos ou na emissão de credenciais de usuários reais.

Referência de protocolo: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.

## Validação

- Reprodução anterior: max_age=0 falhou após TOTP válido; cenários anteriores continuaram passando.
- 37 testes focados passaram: política, recibo, senha, MFA e sessões. Cobertura de GET direto como Fleet e PAR, URL alterada, outra sessão, autenticação diferente, recibo adulterado/expirado, ausência de cerimônia e renovação de sid.
- `dotnet test src/tests/Sufficit.Identity.Tests.csproj -c Release --no-restore --filter 'FullyQualifiedName!~Browser&FullyQualifiedName!~E2e' --nologo`: 1.154 aprovados, um teste de integração NATS ignorado sem infraestrutura.
- `dotnet build src/server/Sufficit.Identity.Server.csproj -c Release --no-restore --nologo -warnaserror`: zero avisos e erros.
- `git diff --check`: sem problemas.
- Logs locais em `/mnt/workspaces/sufficit/tmp/reauth-loop-before.log`, `reauth-loop-full.log`, `reauth-loop-build.log`, `reauth-loop-rollout.log`.

## Publicação

Commit de código: `bfbf7bf8d3a7acf6a7c0bd95f7bbbde3d6f8910c`, integrado e enviado à main.
STS SHA256: `06bb78d2d145cf3ae2741ec1e6ee744bf2de06cc067ef9e6df52f49278bb73bd`.
Rollout coordenado com trava e rollback, em eveo-apps, apoint-apps e castrum-apps. Somente STS.dll/PDB e REVISION substituídos; configuração, certificados, helpers e demais assemblies preservados. Não há migração de banco.
Backup por nó: `/opt/sufficit-identity.before-reauth-loop-20260910T221150Z`.
Serviços ativos, NRestarts=0. Readiness, discovery, JWKS estável, rotas protegidas e assets passaram nos três nós. Readiness público retornou 200.

CI: https://github.com/sufficit/sufficit-identity/actions/runs/34536227376 — aprovado, incluindo testes, container, smoke API-only, gitleaks e auditoria de dependências.
CodeQL: https://github.com/sufficit/sufficit-identity/actions/runs/34536227402 — aprovado.

## Limites

Validação funcional utilizou conta e TOTP efêmeros no host integrado de testes. A sessão real do usuário não foi acessada, e nenhum token foi emitido em seu nome. O usuário deve retomar o login no Fleet após recarregar a página. Fluxos distintos de passkeys/provedores externos não foram ampliados nesta correção do retorno de senha/MFA.
