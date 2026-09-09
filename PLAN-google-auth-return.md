# Plano — retorno OAuth para Genius

1. [concluído] Inspecionar protocolo e isolar mudanças de outros trabalhos.
2. [concluído] Persistir revisão de autorização e retorno popup; testar callback/refresh/retorno.
3. [em andamento] Validar suíte, documentar e enviar PR.

Sem alteração de credenciais reais. Revisão muda somente em callback bem-sucedido; refresh a preserva. Retorno nativo continua validado por cliente. Aceitação: teste com grant antigo, callback novo, refresh e popup/app.

Validação: 5 testes direcionados e 1067 testes da suíte passaram; faltam build da solução, evidência do navegador e entrega. Nenhuma credencial real utilizada.
