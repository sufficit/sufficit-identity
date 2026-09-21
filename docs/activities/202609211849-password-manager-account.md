# Identificação da conta para gerenciadores de senha

## Objetivo e ponto de partida

Informar o e-mail da conta ao gerenciador de senhas nas telas de alteração e redefinição, conforme autorização do usuário. Continuação do fluxo de commit, push, merge e deploy já autorizado nesta conversa.

Árvore inicialmente limpa em main `35d3b01`, com release `20260921T212142Z-ed15a63`. As senhas já usavam autocomplete=new-password; no reset, o e-mail aparecia apenas como texto. O cadastro já possuía seu campo de identificação e não precisou de alteração.

## Implementação e decisões

- Novo componente compartilhado `PasswordManagerAccount`: input de texto com name=username e autocomplete=username, oculto do layout, dentro do mesmo formulário das senhas. A marcação segue a orientação do [Chromium sobre formulários reconhecidos](https://www.chromium.org/developers/design-documents/form-styles-that-chromium-understands/) e [formulários de senha](https://www.chromium.org/developers/design-documents/create-amazing-password-forms/).
- Redefinição fornece o e-mail resolvido pelo serviço somente depois de validar o token. Token inválido não revela e-mail nem renderiza o formulário.
- Alteração obtém o perfil do usuário autenticado pelo contrato GetProfileAsync; usa o e-mail, com fallback para UserName quando não há e-mail.
- O novo campo é apenas uma indicação para o navegador. Seu valor enviado não seleciona a conta nem participa do comando de troca: token validado e principal autenticado continuam sendo a autoridade.
- Preservados POST estático, nomes dos campos de senha, autocomplete, política efetiva e componente de dicas pendentes. Nenhuma dependência, migration ou configuração nova.
- Aplicação proporcional das skills software-development, Refero e Sufficit Frontend: componentes existentes e direção visual preservados; não há elemento visível novo.

## Validação

- 32 testes direcionados aprovados, zero avisos: PasswordFormTests, AccountSelfServiceTests e PublicAuthenticationBoundaryTests.
- Os nove cenários de formulário conferem a identificação dentro do form correto e adulteram username antes do POST. Sucesso, erros e hash da conta correta permanecem válidos; o campo não muda a conta alvo.
- Novo teste cobre ausência de identificação e de formulário para token inválido de uma conta existente.
- Roteiro versionado `scripts/check-password-guidance.mjs` passou em cadastro, alteração e reset no navegador: identificação no form e oculta quando aplicável, edição/colagem/change, regras pendentes, acessibilidade e mobile.
- Fluxos com e sem JavaScript aprovados em pt-BR/en-US: senha curta, confirmação divergente, senha atual incorreta, sucesso e limpeza dos campos. As verificações de credenciais usam Identity/SQLite isolados; o host de revisão visual usa serviços simulados.
- Build do host, publicação Release e git diff --check aprovados. Hosts e navegadores temporários encerrados.
- [CI do PR](https://github.com/sufficit/sufficit-identity/actions/runs/35658402443): **1.594 testes aprovados, 1 ignorado, zero falhas**. Build com avisos como erros e demais gates do pipeline aprovados. [CodeQL do PR](https://github.com/sufficit/sufficit-identity/actions/runs/35658402483) aprovado.

[CI do merge](https://github.com/sufficit/sufficit-identity/actions/runs/35658897073) e [CodeQL do merge](https://github.com/sufficit/sufficit-identity/actions/runs/35658896776) também aprovados.

## Entrega

[PR #82](https://github.com/sufficit/sufficit-identity/pull/82), commit `e604d81a4165c233ce78efd796498a42f3bb8a0d`, integrado em `bef68724a960b6a23e4772e9f0f8f98cbf7ff47e`. A árvore do merge foi comparada com a revisão aprovada e é idêntica.

- Release: `20260921T214421Z-bef6872`.
- Arquivo: `/tmp/identity-manager-releases/20260921T214421Z-bef6872.tar.gz`.
- SHA-256 do arquivo: `0f5d33af87c9e6c32fa66519730c3bef4a749e332d51ac47845e8be5ce599098`.
- SHA-256 de Sufficit.Identity.UI.dll: `8e9ecfbaf1d474a92298bf8b429ad76424b24c210a4a60b2390abebc1a4779dd`.
- SUI local limpo: `cf71a685cedf1cf5e2e8f1dd0136fb571acbc38b`.
- Empacotamento e preparação pelos helpers canônicos, integridade conferida e quatro configurações preservadas por nó. Plano temporariamente ignorado somente pelo info/exclude local para permitir empacotamento limpo.
- Migrator executado uma vez em eveo: Result=success, ExecMainStatus=0, sem migrations novas.
- Ativação por activate-cluster-release.sh sob lease, na sequência eveo → apoint → castrum. Sem rollback; release anterior preservada. Os 502 transitórios de inicialização terminaram dentro da espera de saúde.

| Nó | Revisão | Verificação após ativação |
| --- | --- | --- |
| eveo-apps | bef6872 | ativo, health/ready Healthy, UI idêntica ao artefato |
| apoint-apps | bef6872 | ativo, health/ready Healthy, UI idêntica ao artefato |
| castrum-apps | bef6872 | ativo, health/ready Healthy, UI idêntica ao artefato |

Cada nó também apresentou o componente no binário, cadastro com mínimo de oito caracteres e reset inválido sem identificação nem formulário. Certificado SHA-256 `5e858b8d138993436730db83743ac67183495e44de8e2e041e72b2882410eefb` e JWKS SHA-256 `85d43862afae2e2eea21c6668aa9ec34fa0c029ac906cd0eaee9122847aed769` preservados e uniformes.

Smoke no domínio público aprovado: login anterior, indicação de e-mail, senha vazia, link Google, JS/CSS, cadastro hidratado, reCAPTCHA, antiforgery e dicas pendentes. Mobile sem overflow ou exceções JavaScript. Nenhum cadastro/login foi enviado e nenhuma conta real foi alterada.

## Evidências e limites

Evidências temporárias: `/tmp/identity-manager-ci.log`, `/tmp/identity-manager-package.log`, `/tmp/identity-manager-package.env`, `/tmp/identity-manager-artifact.json`, `/tmp/identity-password-manager-node-check.py` e `/tmp/identity-password-pending-public-smoke.cjs`.

A alteração fornece os metadados esperados para associar conta e senha; a oferta nativa de geração depende do perfil e das configurações do gerenciador. Não foi testado um perfil pessoal conectado ao Google. As telas protegidas foram verificadas no ambiente isolado; produção recebeu apenas consultas e smoke sem submissão. Páginas já abertas precisam ser atualizadas.

Este relatório registra a publicação dos binários. O plano temporário será encerrado após sincronizar a documentação, sem nova publicação de binários.
