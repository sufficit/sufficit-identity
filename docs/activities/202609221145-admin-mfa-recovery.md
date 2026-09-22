# Recuperação administrativa da autenticação de dois fatores

## Objetivo e ponto de partida

Entregar a ação em Gerenciamento → Usuários → Editar e publicar em produção, conforme pedido explícito do usuário. Repositório inicialmente limpo em main de90d7e; produção uniforme em bef6872. Não houve redefinição de conta real como teste.

## Implementação e decisões

- Serviço compartilhado pela UI e `POST /api/users/{id}/reset-two-factor`. Exige `identity.users.reset-mfa` e leitura do titular, política de alvos protegidos, sessão humana com MFA apresentado nos últimos 15 minutos; proíbe autorredefinição. Não usa exceções de máquina nem relaxamento do gate geral.
- Confirmação contextual com motivo de 10–500 caracteres, identificação exata do alvo e declaração de verificação da identidade pelo suporte. A declaração humana não autentica nem autoriza o operador.
- Transação invalida chave TOTP/códigos de recuperação/security stamp, revoga tokens/autorizações/sessões do alvo e persiste auditoria. Rollback preserva as credenciais se a mutação falhar.
- Marcador interno não secreto em usertokens obriga recadastro. Navegação leva à configuração; OAuth e gerenciamento permanecem bloqueados até novo TOTP válido e códigos gerados. Endpoints de protocolo preservam a semântica de prompt=none com interaction_required.
- E-mail após commit pelo transporte existente, sem segredos. Falha do aviso é sinalizada separadamente e não mascara uma redefinição concluída. Senha, passkeys e bloqueio permanecem preservados.
- Componente reutilizado nos detalhes e edição; recursos pt-BR/en-US e estados de permissão, MFA recente, confirmação, processamento, erro e sucesso. Runbook permanente em docs/runbooks/RUNBOOK-ADMIN-MFA-RECOVERY.md.
- Skills software-development, sufficit-frontend e Refero aplicadas proporcionalmente: referência visual travada nos painéis existentes de credenciais, componentes/tokens SUI e confirmação contextual já usada pelo gerenciamento. Ledger: posição/ação vêm do pedido; densidade/tipografia/controles vêm do painel existente; textos de consequência e prevenção de duplicidade vêm do fluxo de credenciais sensíveis. Nenhuma dependência, migration ou configuração de produção adicionada.

## Validação e triagem

- Duas rodadas locais completas com navegador: 1616 aprovados, 1 ignorado (NATS), zero falhas; Release com avisos como erros. Depois do ajuste OAuth, 27 testes direcionados aprovados, incluindo dois novos casos de autorização interativa/silenciosa.
- Playwright isolado conferiu campos obrigatórios, confirmação exata, cancelar/limpar, sucesso/recadastro, desktop/mobile e en-US. Capturas inspecionadas em /tmp/identity-mfa-screenshots. Nenhuma conta real alterada.
- Cobertura de autorização real, negação por capacidade/MFA/nível do alvo, isolamento entre usuários, revogação de códigos e sessões, rollback, falha de notificação e emissão OAuth bloqueada.
- Contratos locais corrigidos durante validação: ordem explícita do middleware e limite de linhas com extração do stub para ManagementUiRoutingTests.UserServiceStub.cs; arquivo parcial Users.cs original preservado. Teste global de telemetria usa ConcurrentQueue para receber medições concorrentes da suíte paralela.
- CodeQL: quatro fluxos de log forging corrigidos com remoção de CR/LF, conforme [documentação da regra](https://codeql.github.com/codeql-query-help/csharp/cs-log-forging/). Alerta #201 triado explicitamente como falso positivo: o campo IdentityVerified é atestado adicional após autorização incondicional por capacidade/objeto/MFA. Justificativa registrada no alerta e no PR; nenhuma regra do scanner desabilitada. A análise da revisão intermediária foi substituída automaticamente pela nova revisão via concurrency/cancel-in-progress; não foi cancelamento manual nem reexecução cega.

## Entrega

[PR #83](https://github.com/sufficit/sufficit-identity/pull/83), revisão aprovada `6f65ef72633a2bca49d9f6bee83827ee82013fdf`, integrada em `79ac073e8fb73f958c17c523a97a8d06142bb1d8`. A árvore foi comparada e é idêntica: `b52738b84627ed784528ad09865cc995034da58c`. O pacote conserva o REVISION do commit aprovado, ancestral do merge.

[CI final](https://github.com/sufficit/sufficit-identity/actions/runs/35741613297): **1618 aprovados, 1 ignorado, zero falhas**, MariaDB temporário, Docker, build com warnaserror, auditoria de dependências e secret scan aprovados. [CodeQL final](https://github.com/sufficit/sufficit-identity/actions/runs/35741613290) e check semântico aprovados.

- Release: `20260922T143745Z-6f65ef7`.
- Arquivo: `/tmp/identity-mfa-releases/20260922T143745Z-6f65ef7.tar.gz`.
- SHA-256: `a4cc175872a14b999e17ba8727aea4018c73dbe1b70142893ecc374dd105f96b`.
- SUI local limpo `cf71a685cedf1cf5e2e8f1dd0136fb571acbc38b`, usado no publish conforme DEPLOY.md.
- Empacotamento e preparação canônicos, quatro configurações preservadas por nó, sem segredos no arquivo local.
- Migrator executado uma vez em eveo: Result=success, ExecMainStatus=0, sem migrations novas.
- Ativação pelo helper de cluster sob lease, eveo → apoint → castrum. Sem rollback; release anterior preservada. 502 transitórios durante inicialização terminaram dentro da espera de saúde.

| Nó | Revisão ativa | Verificação |
| --- | --- | --- |
| eveo-apps | 6f65ef7 | ativo, health/ready Healthy, assemblies idênticos ao artefato |
| apoint-apps | 6f65ef7 | ativo, health/ready Healthy, assemblies idênticos ao artefato |
| castrum-apps | 6f65ef7 | ativo, health/ready Healthy, assemblies idênticos ao artefato |

SHA-256 dos assemblies verificados nos três nós:

- Management: `9f00868ce04d3a061cdf70c4cdb8feb088a77dd81720cae9c353c40f033ff39a`.
- UI.Management: `b63933dadbb914e36aecd0798b1c10444750215f0f774d79d2687d1c9bf36cca`.
- STS: `d727d0dddaf4dd48b8a055d125a54f5737fc13e1fe00a0c1373e9c421ca80441`.
- Core: `09498d23f1db9277b54cfacfaae6e686b0acc18d869608cf26624695cec8603f`.

Certificado `5e858b8d138993436730db83743ac67183495e44de8e2e041e72b2882410eefb` e JWKS `85d43862afae2e2eea21c6668aa9ec34fa0c029ac906cd0eaee9122847aed769` uniformes e preservados.

No domínio público, `/management/users` retorna 302 para login e a nova API retorna 401 sem autenticação. Playwright público aprovou login, scripts/CSS, cadastro hidratado, reCAPTCHA, antiforgery e mobile sem overflow ou exceções. Nenhum login/cadastro foi enviado e nenhum usuário real foi redefinido.

Evidências temporárias: `/tmp/identity-mfa-validation.log`, `/tmp/identity-mfa-protocol-tests.log`, `/tmp/identity-mfa-ci-final.log`, `/tmp/identity-mfa-package.env`, `/tmp/identity-mfa-package.log`, `/tmp/identity-mfa-prepare.log`, `/tmp/identity-mfa-migrator.log`, `/tmp/identity-mfa-activate.log`, `/tmp/identity-mfa-artifacts.log` e `/tmp/identity-mfa-public-smoke.log`. Plano temporário acompanhado em docs/plans e excluído somente pelo info/exclude local durante empacotamento; encerrado após o relatório.

## Limites operacionais

Administradores completos recebem a capacidade pelo catálogo; perfis granulares precisam de concessão explícita. O gestor deve confirmar a identidade pelo suporte e orientar o titular a cadastrar o novo autenticador e guardar os códigos. Um aviso enfileirado não comprova recebimento.

JWT já entregue a consumidor que valida apenas assinatura pode continuar aceito até expirar. A revogação central depende de introspecção/consulta de estado ou reação a eventos no consumidor. Não retornar a binários que desconhecem o marcador de recadastro enquanto houver recuperações pendentes. A interface protegida foi testada em ambiente isolado; smoke de produção não redefine usuários reais.
