# Publicação do escopo de tokens pessoais

Pedido: commit, push e deploy da correção de escopo e diagnósticos de emissão de tokens pessoais. Skill software-development orientou checkpoints e registro de evidências.

## Revisão e configuração

- Código Identity: `823c74e0add6d250de628afa8a1d83dcabd62ae4`, main enviada.
- Release: `20260908T200807Z-823c74e`, eveo-apps, apoint-apps, castrum-apps.
- Arquivo SHA256: `0c3ccf4431f4ec61d744b5b9792751fa99691d5cba47129c03351434d7d7bba7`.
- Configuração ativa `Sufficit:Identity:PersonalTokens`: RequiredScope `personal.tokens.manage`, ScopeClientIds incluindo `SufficitBlazorServer`. Nenhuma outra política alterada.
- Backups de appsettings.Production.json no release anterior, sufixo `.before-personal-token-20260908T200831Z` no eveo, `200832Z` no apoint e `200833Z` no castrum. Configurações e segredos não foram adicionados ao Git nem ao arquivo de publicação.

## Execução e validação

Build Release e 18 testes de provisionamento/política/controller aprovados sem warnings, usando `-p:SufficitUseLocalSui=false`. Evitou incorporar mudança de versionamento alheia presente no checkout SUI. Lockfiles preservados.

`SufficitUseLocalSui=false bash helpers/package-release.sh`, seguido de prepare-cluster-release.sh e activate-cluster-release.sh com chave SSH operacional. Prepare herdou quatro configurações por nó; ativação sequencial com lease e rollback automático. Verificador final confirmou revisão exata, serviços active, health e ready Healthy nos três servidores, mesmos hashes de certificado e JWKS. Houve 502 temporário durante inicialização, recuperado pelo health gate antes de avançar ao próximo nó.

Discovery consultado individualmente nos três nós anuncia `personal.tokens.manage`. Journal do eveo registra a concessão do escopo a `SufficitBlazorServer`; os demais nós compartilham banco e não repetem a concessão idempotente.

## Limites da entrega conjunta

Blazor `a22973e16e733a78edefce9cc02ea724d4b93ab3` commitado e enviado à main; sete testes de contrato passaram, sem warnings. **Blazor não publicado**: build completo falha NU1605/NU1107/NU1202 em dependências e checkout tem mudanças ACD/SUI alheias. Histórico CI run 31961724374 informa bloqueio por faturamento/limite GitHub Actions; nenhuma execução nova encontrada para o commit até esta conferência.

Não foi emitido token real de usuário. MFA, recência, validade e titularidade permanecem exigidos. Necessária nova autenticação quando o cliente Blazor passar a pedir o novo escopo. Não houve deploy de Endpoints.
