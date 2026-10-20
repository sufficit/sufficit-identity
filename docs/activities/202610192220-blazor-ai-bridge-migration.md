# Migração do client de serviço Blazor AI

Autorização explícita do usuário nesta sessão: “migre e ajuste”. Origem sufficit_blazor_ai_bridge; destino sufficit-blazor-ai-bridge. Escopo ai.bridge, audiência sufficit-ai, grant client_credentials. Não conceder manager/administrator para resolver acesso do catálogo.

Plano: criar cliente confidencial novo e segredo aleatório; validar token antes de atualizar consumidores; ajustar Eveo/Apoint/Castrum e validar token/API/health. Preservar cliente legado e backups protegidos nesta etapa. Não emitir/resgatar voucher.

API canônica /api/clients exige política sufficit-identity-management; não há credencial administrativa dessa API disponível nesta sessão. Provisionamento administrativo direto na tabela identity.applications, auditado neste documento, usando acesso SSH existente ao eveo-data. Reutilizar formato de hash OpenIddict do helper oficial; segredo nunca em argumentos, logs ou Git. Operação aditiva, não altera o cliente legado nem usuários/roles.

Inventário anterior: Eveo com client legado/ai.bridge em /etc/sufficit/blazor-prompt-audio.env; Apoint e Castrum sem credenciais de serviço carregadas. Endpoint legado retorna 401 invalid_client/ID2055. Cadastro com hífen ausente no banco; scopes ai.bridge e alias legado já usam audiência sufficit-ai.

## Resultado confirmado

Cliente sufficit-blazor-ai-bridge criado com segredo aleatório e hash no formato OpenIddict. Permissões somente client_credentials, endpoint token e scope ai.bridge; audiência sufficit-ai. Entitlement direto no client: aiuser:d21cfb04-9d37-473b-837c-67591a26feed. Nenhuma role manager/administrator. O contexto vazio de AIUser é self-context e não atende a subject textual de máquina, por isso foi substituído pelo contexto explícito Sufficit após validação.

Identity configurado nos três hosts apps para emitir JWT somente para esse novo client (`Sufficit:Identity:Tokens:AccessTokenFormatsByClient:sufficit-blazor-ai-bridge=Jwt`). Backups protegidos em /root/identity-backups/blazor-bridge-migration/appsettings.Production.before.json. Token de referência não autenticou o consumidor AI; JWT autenticou. Escopo sozinho não materializava entitlement para client_credentials; a concessão direta acima resolveu o 403 sem conceder administração.

Eveo/Apoint/Castrum atualizados em /etc/sufficit/blazor-prompt-audio.env (0600). Backup de cada arquivo em .before-client-migration-20261020. Credenciais efetivamente carregadas conferidas pelo ambiente dos processos após reinício. Nos três hosts: token HTTP200, GET https://ai.sufficit.com.br/openai/v1/models HTTP200, Identity/Blazor active; health local HTTPS Blazor Healthy. Discovery público Identity HTTP200. O cadastro antigo foi preservado, mas nenhum dos três consumidores Blazor usa mais seu id. Segredos temporários locais removidos ao terminar.

O endpoint de sincronização pendente no PR AI90 foi separado da política manager: exige AIUser, client_id autorizado por aplicação e sub igual ao client_id, recusando token delegado de usuário. 16 testes passaram após o ajuste. Nenhuma nova versão do catálogo foi publicada nesta migração; PR Blazor193 com CI aprovado, AI90 aguardando CI (execução anterior falhou no download externo do FFmpeg por SSL timeout).
