# Arquivamento self-service de tokens inativos

O assistente da página de tokens do Blazor precisava retirar expirados/revogados
da lista. O DELETE existente continua apenas revogando, sem alteração contratual.

Foi adicionado `POST /api/account/tokens/{id}/archive`, autenticado com o bearer
do próprio usuário. Aceita apenas referência access_token/legacy_reference_token
do proprietário e estado revoked/redeemed ou expiração atingida. Ativos e estados
ambíguos não expirados retornam 409; outro proprietário/tipo/referência ausente
retornam 404. Arquivamento repetido é idempotente.

Uma atualização concorrente grava status revoked e `urn:sufficit:token:archived_at`.
O registro, payload e identificador permanecem no banco para histórico; listas
omitem arquivados e a API de edição os recusa. Não há migração de esquema.

Validação: 18 testes PersonalTokensTests aprovados com
`dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore -p:SufficitUseLocalSui=true --filter FullyQualifiedName~PersonalTokensTests -v quiet`.
O restore local SUI resolveu CS1704 causado por assets NuGet/projeto misturados;
os lockfiles gerados foram restaurados exatamente ao estado anterior.
Build STS sem erros/warnings e diff-check limpo.

Não houve alteração de tokens reais nem publicação. Esta rota precisa estar
disponível antes do Blazor que a consome. A prévia/consentimento de lote fica no
adapter do Blazor, mas autorização, tipo, expiração e concorrência são verificados
novamente neste endpoint. Registro completo e contrato no projeto sufficit-blazor,
`docs/activities/202609091003-personal-token-ai.md` e
`docs/architecture/personal-token-ai.md`.
