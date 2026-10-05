# Reenvio de confirmação pela gestão e confirmação por provedor verificado

## Objetivo e ponto de partida

Usuário `c58fee7c-50ff-4add-8042-c21290594d23` cadastrou-se por e-mail/senha (Gmail), não confirmou, e o login pelo Google retornava `not_allowed`. A gestão não oferecia reenvio da confirmação (a API `POST api/users/{id}/resend-confirmation` existia, sem botão).

## Implementação e decisões

- Detalhe do usuário na gestão: ação "Reenviar e-mail de confirmação" junto ao status Pendente, sob `identity.users.confirmation` (flag `CanResendConfirmation` em `ManagementUserActions`). Resultado em aviso inline, padrão da UI de gestão. Fica fora das páginas dedicadas de `202609221251-user-management-action-wizards.md` (uma tarefa por URL) de propósito: é um clique, sem formulário, sem efeito destrutivo e só faz sentido com a confirmação pendente; a grade de ações segue com as quatro operações sensíveis.
- `IAccountOnboardingService.SendEmailConfirmationAsync(userId)` envia para a conta resolvida e devolve o desfecho real (`Sent`, `AlreadyConfirmed`, `MissingEmail`, `NotFound`, `Failed`). O caminho anterior relia pelo e-mail (nada enviado com e-mail compartilhado) e sempre devolvia `Accepted`, então a auditoria registrava sucesso mesmo com falha de entrega.
- Reenvio público não envia mais para conta já confirmada (resposta continua `Accepted`, sem enumeração).
- Login externo com e-mail verificado (decisão `Immediate`) para conta existente NUNCA confirmada: confirma a conta em vez de `NotAllowed`. Antes, revoga as credenciais vinculadas sem prova de posse — senha, logins externos, 2FA/autenticador — e troca o security stamp. A revogação precede a confirmação: falha parcial deixa a conta não confirmada. Mantém a defesa de pre-hijacking; o dono define senha pela recuperação.
- Asserção não verificada continua em `AccountLinkRequiresSignIn` sem tocar na conta.

## Validação

- Build Release `-warnaserror` e suíte em container SDK 10 (modo pacote): 1649 aprovados, 1 ignorado, 1 falha ambiental (`DeploymentHardeningTests.Vault_environment_file...`, script de deploy no container), sem relação.
- Testes novos: confirmação por asserção verificada com revogação; asserção não verificada intocada; desfecho real do envio pelo operador.
- CI do commit ficou na fila do runner hospedado durante o deploy.

## Entrega

- Commit `78833455a2b1f953f6e91455c97d0905d9bc52f7`; produção anterior `20261005T003450Z-9bceed1` (diferença fora de docs só comentário).
- Release `20261005T194000Z-7883345`, SHA-256 `ed7d4c712a586da833114a1fd4fd7b11a435f1b55a596080a33da4ba9e675808`, empacotada em modo pacote (`SufficitUseLocalSui=false`): o SUI irmão local estava numa refatoração que quebra consumidores. `Sufficit.Blazor.UI.dll` idêntica à release anterior.
- Sem migrations. Prepare (4 configs preservadas por nó) e `activate-cluster-release.sh` node-a → node-b → node-c, sem rollback. Cluster uniforme, health/ready Healthy, cert `5e858b8d…` e JWKS `85d43862…` preservados. wwwroot sem arquivo ilegível nos 3 nós.
- Smoke público `/account/login`: sem erro de console, sem 4xx/5xx, Google e link de reenvio presentes. Tela de gestão não exercitada em produção (exige sessão de operador).
