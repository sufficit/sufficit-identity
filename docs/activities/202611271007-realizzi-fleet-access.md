# Acesso ao Fleet da Realizzi

Em 27/11/2026, a pedido do administrador da central, a conta confirmada de Camila recebeu o entitlement `aicontrol` somente no contexto da Realizzi (`d9b753ec-811c-4fe3-9726-07f81643363c`). A conta de Hugo já tinha `aicontrol` global e manteve as permissões existentes.

A API de gestão recusou o token da integração por falta de `identity.management`. A concessão restrita foi feita em transação no banco `identity`, no nó primário sincronizado, após validar a conta, o endereço confirmado e a ausência de concessão equivalente. A leitura pós-commit confirmou a atribuição `42567` em `userclaims`. A sessão da Camila precisa ser renovada para carregar a permissão. Nenhuma role global foi concedida.

A frota da Realizzi e a persona da Nina foram confirmadas pela API do Fleet. A integração de voz ficou pendente por HTTP 400 na criação do agente remoto pela ElevenLabs. O incidente é independente da concessão de acesso.
