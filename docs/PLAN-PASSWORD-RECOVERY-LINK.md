# Recuperação de senha por link

Objetivo: operador solicita envio ao e-mail confirmado da conta; cliente define senha no Identity. Nenhuma senha ou token de recuperação no Blazor.

1. CONCLUÍDO — Dispatch por ID no Identity, endpoint administrativo autorizado e auditado, sem alterar senha/sessões no envio.
2. CONCLUÍDO — Substituir diálogo de senha no Blazor por confirmação do envio, sidecar IA somente leitura.
3. CONCLUÍDO — Testes de envio/negação/falha, senha intacta, transporte sem senha e builds.
4. CONCLUÍDO — Registro de entrega e integração à main local em Identity/Blazor, preservando mudanças externas e código recente de cobrança de serviços.
5. EM ANDAMENTO — Publicação coordenada aguardando decisão sobre navegação/aparência externas no checkout Blazor. Nenhum push de main ou deploy deste fluxo foi executado.

Escopo: fluxo administrativo de recuperação, modelos genéricos de identidade. Presets/permissões não mudam. Referência visual: ações atuais da tela de usuários.

Validação: 42 testes Identity e 39 Blazor passaram; suíte de provisionamento Identity excluída por erro de sintaxe preexistente e SUI publicado usado. Publicação ainda depende da decisão de navegação externa no checkout Blazor.
