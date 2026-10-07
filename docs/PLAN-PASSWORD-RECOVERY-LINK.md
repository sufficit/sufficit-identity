# Recuperação de senha por link

Objetivo: operador solicita envio ao e-mail confirmado da conta; cliente define senha no Identity. Nenhuma senha ou token de recuperação no Blazor.

1. CONCLUÍDO — Dispatch por ID no Identity, endpoint administrativo autorizado e auditado, sem alterar senha/sessões no envio.
2. CONCLUÍDO — Substituir diálogo de senha no Blazor por confirmação do envio, sidecar IA somente leitura.
3. CONCLUÍDO — Testes de envio/negação/falha, senha intacta, transporte sem senha e builds.
4. CONCLUÍDO — Registro de entrega e integração à main local em Identity/Blazor, preservando mudanças externas e código recente de cobrança de serviços.
5. CONCLUÍDO — Adaptadores genéricos Identity mantêm T e delegam ao SUI; build local e pacote passaram sem erros.
6. CONCLUÍDO — Builds local/pacote e 106 testes com SUI local passaram, incluindo renderização real do campo. Helpers aceitam host de saúde configurável; bash -n passou.
7. CONCLUÍDO — Identity e Blazor publicados nos três hosts por entrypoints oficiais; saúde/ready, hashes, certificado/JWKS e navegador público conferidos. Blazor preserva árvore autorizada com navegação/aparência e publicação concorrente equivalente.

Escopo: fluxo administrativo de recuperação, modelos genéricos de identidade. Presets/permissões não mudam. Referência visual: ações atuais da tela de usuários.

Validação: 106 testes Identity com SUI local e 39 Blazor passaram; suíte de provisionamento Identity excluída por erro de sintaxe preexistente. Builds com SUI local e pacote publicados passaram. Nenhum reset/envio real ou teste autenticado de cliente em produção. Blazor é deploy manual de árvore autorizada parcialmente não commitada; futuro CI de checkout limpo pode substituí-lo. Nenhum push desta tarefa.
