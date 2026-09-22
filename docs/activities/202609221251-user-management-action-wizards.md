# Ações de usuário em fluxos dedicados

## Objetivo

Simplificar a tela de detalhes do usuário no gerenciamento após o retorno do uso real em celular. Os painéis de redefinição de MFA, controle de acesso, redefinição de senha e exclusão ficavam abertos em sequência e alongavam a página. A entrega mantém essas operações recolhidas e dedica uma URL a cada função.

Ponto de partida: `main` em `8572057`; produção uniforme em `28fbc942b80ee12d5c29d6c43a511106bbf9a573`.

## Implementação e decisões

- O detalhe do usuário mostra apenas o botão **Ações da conta**, recolhido por padrão. Ao abrir, aparece uma lista compacta; ao fechar, o conteúdo é removido do layout e não reserva espaço.
- As operações usam as rotas `/users/{id}/actions/mfa`, `/access`, `/password` e `/delete`, todas com retorno explícito ao usuário e uma única tarefa por página.
- A tela `/users/{id}/edit` voltou a tratar somente o perfil.
- A redefinição de MFA conserva permissões, MFA recente, confirmação nominal, declaração de verificação da identidade, auditoria e revogações. O motivo passou de textarea para input de uma linha, mantendo o contrato de 10–500 caracteres.
- Estados de carregamento, indisponibilidade, acesso negado, step-up, sucesso e erro foram preservados nas novas páginas. Nenhum serviço, contrato de segurança, migration, dependência ou configuração mudou.

Ledger visual:

- Separação por URL, uma função por tela, toggle e motivo em uma linha: pedido explícito do usuário.
- Hierarquia, tipografia, botões, status, cores e espaçamentos: componentes e tokens já usados pelo gerenciamento/Sufficit.Blazor.UI.
- Lista compacta de ações: derivada da hierarquia da tela existente e da referência visual fornecida, removendo os quatro cartões simultâneos.
- Confirmações e avisos dentro de cada fluxo: regras de credenciais sensíveis já existentes, mantidas na ação correspondente.
- Skills aplicadas: software-development, sufficit-frontend, Refero Design e Impeccable. O detector Impeccable encontrou apenas avisos preexistentes de fonte/acento fora das linhas alteradas.

## Validação

- Build Release com avisos como erros aprovado.
- Suíte local completa: **1.627 testes aprovados, zero falhas**; o teste NATS opcional permanece fora do resumo compacto do RTK.
- CI do [PR #85](https://github.com/sufficit/sufficit-identity/pull/85): build/test, MariaDB, container, secret scan, auditoria de dependências e CodeQL aprovados.
- Playwright isolado validou toggle abrir/fechar, ausência dos formulários no detalhe, quatro links/URLs, motivo de MFA em input, confirmação, cancelamento, sucesso e estado de recadastro.
- Viewports de 1440×1000 e 390×844 sem overflow horizontal. Telas móveis de menu, MFA, acesso, senha e exclusão inspecionadas visualmente.
- Recursos pt-BR/en-US, XML, JavaScript e whitespace validados.

## Entrega

[PR #85](https://github.com/sufficit/sufficit-identity/pull/85), commit funcional `72e285b8d5fba2f71e62ebc215a7e145c2abcaaa`, integrado em `04b91e8655af2300b2cbf59ec2230635253bfa10`.

- Release: `20260922T154719Z-04b91e8`.
- Arquivo: `/tmp/identity-user-actions-releases/20260922T154719Z-04b91e8.tar.gz`.
- SHA-256: `83eb986a81e1b2c4e0d0f76c971d25215fdeba938eecbf3ae63c943ceba01b21`.
- Três candidatos preparados com quatro configurações herdadas do release anterior por nó.
- Migrator executado uma única vez em eveo: `Result=success`, `ExecMainStatus=0`; a entrega não contém migrations.
- Ativação serial sob lease em eveo, apoint e castrum, sem rollback. Os 502 transitórios de inicialização terminaram dentro do gate do helper.
- Três nós ativos em `04b91e8655af2300b2cbf59ec2230635253bfa10`, serviço ativo e health/ready Healthy.
- Assembly `Sufficit.Identity.UI.Management.dll` idêntico ao artefato nos três nós: `227603dd31503503ca01240f17011bd71bb3d17f735ee998c3e1b9e17d9bd6d0`.
- Certificado `5e858b8d138993436730db83743ac67183495e44de8e2e041e72b2882410eefb` e JWKS `85d43862afae2e2eea21c6668aa9ec34fa0c029ac906cd0eaee9122847aed769` preservados e uniformes.
- Smoke público: login 200, gerenciamento anônimo 302 para login e CSS publicado contém o novo seletor. Zero entradas de prioridade `err` no journal dos três serviços desde a ativação.

As operações autenticadas foram exercitadas no host isolado de testes. O smoke de produção não executou nenhuma alteração em conta real; o gestor pode validar o novo fluxo diretamente no gerenciamento.

Evidências temporárias: `/tmp/identity-user-actions-package.env`, `/tmp/identity-user-actions-package.log`, `/tmp/identity-user-actions-prepare.log`, `/tmp/identity-user-actions-migrator.log`, `/tmp/identity-user-actions-activate.log`, `/tmp/identity-user-actions-verify.log` e `/tmp/identity-mfa-screenshots/`.

## Ajuste responsivo posterior

Após a primeira publicação, o usuário esclareceu que o recolhimento deve ocorrer apenas quando faltar espaço. O [PR #86](https://github.com/sufficit/sufficit-identity/pull/86) passou a exibir as quatro ações em uma única linha acima de 960 px, ocultando o botão de toggle. Até 960 px, o seletor permanece recolhido por padrão; abaixo de 768 px, abre como lista vertical. A semântica, as URLs e os fluxos dedicados não mudaram.

- Commit funcional `4e0b201`, integrado em `cfb7bcc87bb4ef5b5519f60b9c0c769ab6de4dd1`.
- Suíte local novamente aprovada: **1.627 testes, zero falhas**. CI, CodeQL e secret scan do PR também aprovados.
- Playwright confirmou quatro ações na mesma coordenada vertical em 1440 px, toggle invisível no desktop, menu fechado por padrão em 390 px e ausência de overflow nas duas resoluções.
- Release `20260922T161302Z-cfb7bcc`, arquivo `/tmp/identity-user-actions-releases/20260922T161302Z-cfb7bcc.tar.gz`, SHA-256 `8d13cb1974590af96bbcf3af0f796d85abbaf282cd767cd004529d9d79c06a61`.
- Migrator único em eveo: `Result=success`, `ExecMainStatus=0`; nenhuma migration nova.
- Três nós ativos e saudáveis em `cfb7bcc87bb4ef5b5519f60b9c0c769ab6de4dd1`, certificado e JWKS preservados.
- Assembly UI.Management uniforme e idêntico ao artefato: `594a5a0e95c667d9f641066e600535d3565fe6221d653a644b3b9b15765d73e6`.
- CSS público contém a grade responsiva nova; login 200 e gerenciamento anônimo 302. Zero entradas de prioridade `err` desde o restart nos três nós.

Evidências adicionais: `/tmp/identity-user-actions-responsive-package.env`, `/tmp/identity-user-actions-responsive-package.log`, `/tmp/identity-user-actions-responsive-prepare.log`, `/tmp/identity-user-actions-responsive-migrator.log`, `/tmp/identity-user-actions-responsive-activate.log` e `/tmp/identity-user-actions-responsive-verify.log`.
