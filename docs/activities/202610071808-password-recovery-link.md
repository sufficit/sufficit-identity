# Link administrativo de recuperação

Adicionado dispatch por ID com resultado tipado no onboarding, endpoint password-recovery e serviço de gestão autorizado/auditado. Callback/token público existente reutilizado; nenhuma alteração de senha/sessões no envio. Stub de interface de gestão atualizado.

42 testes selecionados passaram: seis de envio/negação/falha e fluxo completo com e-mail capturado, mais autorização e revogação existentes. SUI publicado usado; ProvisioningManifestTests*.cs excluídos temporariamente por erro de sintaxe preexistente. Build Management sem erros e composição Server compilou nos testes. Nenhuma conta ou e-mail de produção alterados.

Consumidor Blazor: 38 testes passaram; publicação coordenada ainda pendente de decisão sobre mudanças externas no checkout Blazor (disciplina de AGENTS.md).
