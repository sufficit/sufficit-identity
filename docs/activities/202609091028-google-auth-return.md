# Retorno OAuth e revisão de autorização para Genius

Issue #59 / PR #60; consumidor: sufficit/sufficit-ai-genius#672.

`authorizationRevision` é uma revisão opaca opcional, gravada no token apenas no callback bem-sucedido, exposta nos endpoints status/access e preservada no refresh. Tokens legados continuam legíveis; não é uma credencial nem prova de identidade. O bearer da API continua selecionando o sujeito do Vault.

O authorize aceita `launch_mode=popup`, guardado no estado protegido/persistido. Retorno desktop usa página de conclusão sem token, no-store, nonce CSP e tentativa de fechamento. Quando o navegador bloqueia o fechamento, há botão e instrução para fechar manualmente. Esta página funciona também em deploys API-only, sem dependência do host Blazor/SUI; o retorno nativo dos outros clientes continua validado e preservado. Os modelos foram extraídos do controlador para manter arquivos menores que 400 linhas.

Validação: 1068 testes da suíte passaram; build Release da solução com -warnaserror passou (16 projetos, zero erros/avisos). Seis testes novos do controlador cobrem callback/revisão/refresh, app, recusa, URI e ticket inválidos. Remover a geração da revisão fez a regressão falhar; restauração e testes verdes. A página foi exercitada em Chrome a 1280/390/320 px, claro/escuro, incluindo foco e tentativas de fechamento. Os testes simulam Google e Vault e não usam contas reais.

Implantar esta mudança antes de Genius 0.87.12. Clientes antigos ignoram os campos novos e mantêm o comportamento existente. Não houve deploy de produção, release do Genius, instalação no Windows ou consentimento Google real nesta tarefa. A captura do usuário está na página de consentimento e não prova callback concluído. Não foi alterada a classificação geral de 403. Evidências: /home/hugodeco/.cache/sufficit-ai-genius/google-auth-return/.

A revisão final acrescentou a validação dos escopos antes de salvar o token: consentimento parcial exibe permissões ausentes e preserva o grant anterior. A regressão falha ao remover essa validação. Após restauração: 6 testes direcionados verdes; suíte completa de 1068 e build Release com -warnaserror verdes. A verificação visual conjunta passou em 24 casos, incluindo página de permissões sem fechamento automático.
