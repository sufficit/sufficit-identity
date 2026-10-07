# Recuperação administrativa por e-mail

POST /api/users/{id}/password-recovery, sem corpo, requer autenticação identity.management e capacidade UsersReset, sujeita à política de MFA existente. Resolve conta/destinatário por ID; não aceita nova senha, destinatário alternativo nem retorna token/link.

204 significa envio aceito pelo transporte de e-mail, sem garantia de entrega na caixa postal. Conta sem e-mail ou não confirmado retorna 409; inexistente, 404; falha de despacho, 409. Cada resultado é auditado com recurso usuário, capacidade e código. Token de recuperação não entra em resposta/auditoria.

O envio não altera senha/security stamp/sessões. Cliente define a senha em /account/resetpassword; o fluxo existente valida token e revoga sessões/tokens após sucesso. O endpoint público de recuperação mantém resposta genérica para evitar enumeração.

Blazor deve oferecer apenas envio de link. O contrato administrativo direto antigo do Identity genérico não foi removido nesta alteração; não é usado pelo novo fluxo Blazor. Nenhum modelo de negócio Sufficit foi introduzido no Identity.

## Compatibilidade dos campos SUI

IdentityTextField<T>, IdentitySelect<T> e IdentityNumericField<T> são adaptadores Razor finos na biblioteca compartilhada UI.Components. Herdam o componente SUI correspondente e delegam BuildRenderTree à base. Estabilizam a tipagem Razor entre SUI publicado (T) e checkout local (TValue), mantendo callbacks, foco, validação e DOM do SUI. Não possuem estilos ou lógica de senha próprios. O build local permanece obrigatório para publicação; build no modo pacote também foi validado.
