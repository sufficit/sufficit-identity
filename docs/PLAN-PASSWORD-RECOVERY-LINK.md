# Recuperação de senha por link

Objetivo: operador solicita envio ao e-mail confirmado da conta; cliente define senha no Identity. Nenhuma senha ou token de recuperação no Blazor.

1. CONCLUÍDO — Dispatch por ID no Identity, endpoint administrativo autorizado e auditado, sem alterar senha/sessões no envio.
2. CONCLUÍDO — Substituir diálogo de senha no Blazor por confirmação do envio, sidecar IA somente leitura.
3. CONCLUÍDO — Testes de envio/negação/falha, senha intacta, transporte sem senha e builds.
4. EM ANDAMENTO — Registrar/integrar e publicar conforme regras locais; navegação externa ainda pendente de decisão no checkout Blazor.

Escopo: fluxo administrativo de recuperação, modelos genéricos de identidade. Presets/permissões não mudam. Referência visual: ações atuais da tela de usuários.

Validação: 42 testes Identity e 38 Blazor passaram; suíte de provisionamento Identity excluída por erro de sintaxe preexistente e SUI publicado usado. Publicação ainda depende da decisão de navegação externa no checkout Blazor.
