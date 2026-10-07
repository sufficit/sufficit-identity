# Link administrativo de recuperação

Adicionado dispatch por ID com resultado tipado no onboarding, endpoint password-recovery e serviço de gestão autorizado/auditado. Callback/token público existente reutilizado; nenhuma alteração de senha/sessões no envio. Stub de interface de gestão atualizado.

42 testes selecionados passaram: seis de envio/negação/falha e fluxo completo com e-mail capturado, mais autorização e revogação existentes. SUI publicado usado; ProvisioningManifestTests*.cs excluídos temporariamente por erro de sintaxe preexistente. Build Management sem erros e composição Server compilou nos testes. Nenhuma conta ou e-mail de produção alterados.

Consumidor Blazor: 38 testes passaram; publicação coordenada ainda pendente de decisão sobre mudanças externas no checkout Blazor (disciplina de AGENTS.md).

Integrado à main local de ambos os projetos. Testes Blazor repetidos após incorporar as atualizações locais de cobrança: 38 passaram. Publicação permanece pendente; arquivos externos preservados.

Validação final Blazor: 39 testes passaram, incluindo sidecar somente leitura e resposta serializável para ferramenta desconhecida; build servidor integrado passou sem erros. Nenhum push de main/deploy desta tarefa.

Autorização recebida para incluir navegação/aparência. Conferência mostrou API comercial já Healthy na revisão 94c7bab (busca unificada). Build Identity com SUI local falhou com 46 erros de eventos/componentes; DEPLOY.md exige SUI local, portanto não foi publicada a alternativa com pacote sem decisão do dono. Lockfiles alterados pelo restore foram restaurados ao conteúdo original. Nenhum deploy/push ou envio real nesta tentativa. Evidência: /tmp/password-link-identity-local-sui-build.log.

Validação da árvore Blazor atual autorizada: 39 testes direcionados passaram (Test Run Successful), incluindo transporte de recuperação, busca guiada e tabela compartilhada. Log: /tmp/password-link-current-tree-restored-tests.log. Publicação permanece bloqueada pelo build Identity/SUI local.

Correção autorizada: adaptadores Razor IdentityTextField<T>/IdentitySelect<T>/IdentityNumericField<T> herdam o SUI e delegam integralmente a renderização, estabilizando o parâmetro genérico entre SUI publicado (T) e local (TValue). Consumidores, imports/referência compartilhada e contratos existentes atualizados. Builds dos dois modos passaram; 106 testes com SUI local passaram, incluindo renderização de input senha/valor. Mantida exclusão temporária do arquivo de testes de provisionamento previamente inválido. Helpers canônicos receberam IDENTITY_HEALTH_HOST configurável, necessário porque templates públicos usam example.com; destino de produção configurado sem trocar defaults genéricos. bash -n passou.
