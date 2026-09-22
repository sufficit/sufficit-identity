# Recuperação administrativa do autenticador

Use quando o titular perdeu o autenticador e os códigos de recuperação. Antes da
operação, verifique a identidade pelo procedimento de suporte e registre o chamado;
conhecer a senha ou enviar um pedido por e-mail não comprova sozinho a titularidade.

## Operação

1. No gerenciamento, pesquise em **Usuários** e abra os detalhes ou **Editar perfil**.
2. Em **Redefinir autenticação de dois fatores**, confirme seu próprio segundo fator
   se solicitado. A comprovação deve ter ocorrido nos últimos 15 minutos; dispositivo
   lembrado não basta.
3. Informe o motivo (10–500 caracteres), digite a identificação exibida e confirme
   que verificou o titular. Não inclua senhas, códigos ou documentos no motivo.
4. Confirme a redefinição. Oriente o titular a entrar pelo endereço habitual, ler o
   novo QR code, confirmar um código e guardar os novos códigos de recuperação.

É necessária a permissão `identity.users.reset-mfa`, além de `identity.users.read`.
Administradores completos recebem a nova capacidade pelo catálogo; perfis granulares
precisam de concessão explícita. A proteção de titulares privilegiados continua
valendo. O gestor não pode usar esta operação na própria conta.

## Efeitos e falhas

A transação desativa o TOTP anterior, troca a chave, invalida todos os códigos de
recuperação, altera o security stamp, revoga tokens/autorizações/sessões do titular e
registra operador, motivo e resultado. A senha, passkeys e bloqueio da conta são
preservados. Uma falha antes do commit desfaz a operação inteira.

O estado de recadastro obrigatório é interno, em `usertokens`, sem migration. A
navegação autenticada é encaminhada para `/manage/twofactor`; emissão de credenciais
OAuth e operações de gerenciamento permanecem bloqueadas até a confirmação de novo
TOTP e geração dos códigos. Alterar senha ou desativar 2FA não remove essa pendência.

O aviso é encaminhado ao e-mail confirmado depois do commit, sem senha, chave ou
códigos. Falha no transporte ou ausência de e-mail confirmado produz aviso explícito
para o gestor e auditoria; a redefinição já concluída não deve ser repetida. O gestor
orienta o titular pelo canal verificado. Enfileiramento não comprova recebimento.

Tokens JWT já entregues a serviços que validam apenas assinatura podem continuar
aceitos até expirar; a revogação central depende de introspecção/consulta de estado
ou reação aos eventos de segurança nesses consumidores.

## API e entrega

`POST /api/users/{id}/reset-two-factor` recebe `reason`, `confirmation` e
`identityVerified`; compartilha serviço/autorização com as duas telas. O retorno
contém o estado atualizado e `notificationQueued`, nunca material do autenticador.

Publicar todos os nós antes de disponibilizar a operação. Não retornar a uma versão
anterior a esta proteção enquanto existirem recadastros pendentes: versões antigas
não conhecem o marcador. Falhas de rollout antes do uso seguem o rollback habitual.
