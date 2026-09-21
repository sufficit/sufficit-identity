# Senhas de oito caracteres e instruções pendentes compartilhadas

## Objetivo e ponto de partida

Reduzir o mínimo de novas senhas para 8 caracteres e mostrar somente os requisitos ainda não atendidos, conforme pedido do usuário. Reutilizar os mesmos componentes em cadastro, alteração e redefinição. Continuação do fluxo de commit, push, merge e deploy já autorizado na conversa.

Árvore inicialmente limpa em main `626265d`; release anterior `20260921T205322Z-e9c11d1`. A captura do usuário mostrava a lista estática mesmo com parte dos requisitos atendida. As páginas já reutilizavam PasswordRequirements; alteração/reset usam POST estático e cadastro usa InteractiveServer.

## Implementação e decisões

- `PasswordPolicyOptions.RequiredLength` e template passam de 12 para 8. A projeção para UI continua lendo as opções efetivas do servidor, inclusive overrides. Não há override de comprimento nos três nós de produção.
- Um único `PasswordRequirements` atende as três páginas; cada uma fornece o ID do campo novo e, quando aplicável, seu limite de 100. O componente publica os metadados das regras e suas mensagens localizadas.
- Um único script `password-requirements.js`, carregado pelo App, oculta cada regra atendida, restaura as regras ao apagar e oculta a lista quando não há pendências verificáveis localmente. Cobre input, colagem, change/autofill, retorno à página, reset e substituição de controles em renderização/hidratação.
- O script só lê o campo associado, sem armazenar ou transmitir seu conteúdo. Categorias ASCII, comprimento e unicidade em UTF-16 seguem o comportamento do ASP.NET Identity. A decisão final permanece no servidor.
- A lista não anuncia aceitação da senha. O aviso permanente de vazamento foi retirado; senhas expostas continuam sendo recusadas pelo servidor com mensagem traduzida quando enviadas.
- A associação acessível é retirada quando a lista desaparece e restaurada ao editar, preservando outras descrições do campo. A árvore de acessibilidade do Chromium revelou que apenas ocultar o alvo de aria-describedby ainda fazia todas as regras serem anunciadas; esse defeito foi corrigido antes da integração.
- Sem JavaScript, todas as instruções permanecem disponíveis e a validação continua no servidor. Os campos de POST corrigidos na entrega anterior foram preservados.
- Direção visual: captura fornecida, componentes/tokens SUI e telas atuais; Refero/Sufficit Frontend para clareza e validação. Sem alteração de layout/identidade. O texto passa a ser “O que falta na senha:”.

Os 12 caracteres eram uma configuração do produto. [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/) exige 15 para senha como único fator e permite 8 quando usada como parte de MFA; não estabelece um mínimo universal de 12. A adoção de 8 é decisão explícita do usuário, sem alegação de conformidade NIST. Comentários antigos que confundiam essa referência com o padrão do produto foram corrigidos.

## Validação

- 51 testes direcionados aprovados, zero avisos: formulários, password grant, fronteiras públicas e localização. Cadastro, alteração e redefinição aceitam exatamente 8 caracteres com as demais regras atendidas e rejeitam 7; política personalizada também conferida.
- Restore locked em modo pacote aprovado; 17 testes de formulário/password grant repetidos com o NuGet exato do CI, todos aprovados. Lockfiles preservados em modo pacote. SUI local usado na publicação: checkout limpo `cf71a685cedf1cf5e2e8f1dd0136fb571acbc38b`.
- `scripts/check-password-guidance.mjs` exercitou as três páginas reais em host isolado: digitação, colagem, change, edição, lista vazia/parcial/completa, campos não associados, limite máximo, associação acessível e mobile. O roteiro é reutilizável e não envia formulários.
- Fluxos de POST também aprovados com e sem JS: senha curta, confirmação divergente, senha atual incorreta, sucesso de troca/reset, campos limpos, pt-BR/en-US, desktop e mobile sem overflow. As verificações de senha efetiva usam Identity/SQLite isolados; a revisão visual usa um host com serviços simulados.
- Árvore de acessibilidade confirmou ausência das instruções antigas quando completo. Roteiro repetido nas três páginas após o ajuste. Capturas inspecionadas.
- `git diff --check`, sintaxe JavaScript e publicação Release aprovados.
- [CI final do PR](https://github.com/sufficit/sufficit-identity/actions/runs/35656209448): **1.593 aprovados, 1 ignorado, zero falhas**. Compilação com avisos como erros, contêiner, ensaios SQL, API-only, gitleaks e auditoria aprovados. [CodeQL final](https://github.com/sufficit/sufficit-identity/actions/runs/35656209404) aprovado.

[CI do merge](https://github.com/sufficit/sufficit-identity/actions/runs/35656663276) aprovado com os mesmos 1.593 testes aprovados e 1 ignorado; [CodeQL do merge](https://github.com/sufficit/sufficit-identity/actions/runs/35656663240) também aprovado.

## Entrega

[PR #81](https://github.com/sufficit/sufficit-identity/pull/81), commits `91db3ed` e `e098390`, integrado em `ed15a638b160896bc9bc07ef2c6bd279868d65e6`. A árvore do merge é idêntica à revisão aprovada.

- Release: `20260921T212142Z-ed15a63`.
- Arquivo: `/tmp/identity-pending-releases/20260921T212142Z-ed15a63.tar.gz`.
- SHA-256: `b1adb54bb44e757b5e1b4903b2a4b9ec636c7304a35f1334a0ff8bda235df5d9`.
- Empacotada com `helpers/package-release.sh`, sem configuração/certificados e com REVISION exata. Plano temporário excluído somente pelo info/exclude local durante o empacotamento.
- Preparação por `helpers/prepare-cluster-release.sh`: integridade do arquivo/helper verificada, quatro arquivos de configuração herdados por nó sem alteração.
- Migrator executado uma vez em eveo antes da ativação: Result=success, ExecMainStatus=0. Sem migrations novas.
- `helpers/activate-cluster-release.sh` adquiriu lease do cluster, ativou eveo → apoint → castrum e executou o gate de uniformidade com pins prévios de certificado/JWKS. Sem rollback; os 502 transitórios de inicialização terminaram dentro da espera de saúde.

| Nó | Revisão | Resultado |
| --- | --- | --- |
| eveo-apps | ed15a63 | active/running, Healthy, mínimo 8 |
| apoint-apps | ed15a63 | active/running, Healthy, mínimo 8 |
| castrum-apps | ed15a63 | active/running, Healthy, mínimo 8 |

Certificado SHA-256 `5e858b8d138993436730db83743ac67183495e44de8e2e041e72b2882410eefb` e JWKS SHA-256 `85d43862afae2e2eea21c6668aa9ec34fa0c029ac906cd0eaee9122847aed769` preservados e idênticos. Scripts servidos em cada nó comparados byte a byte com o artefato. NRestarts=0 e nenhum evento error no journal desde 21:22 UTC até a última verificação. Release anterior preservada.

O roteiro versionado passou no domínio público. Uma rodada adicional aguardou hidratação e reCAPTCHA e confirmou login anterior, antiforgery, CSS, edição das dicas após rerender, associação acessível e ausência de exceções JavaScript/overflow. Não houve envio de cadastro/login nem alteração de conta real.

## Evidências e encerramento

Evidências temporárias em `/tmp/identity-password-pending/`, `/tmp/password-pending-*-mobile.png`, `/tmp/identity-password-pending-public-smoke.cjs`, `/tmp/identity-password-pending-public-register.png`, `/tmp/identity-pending-package.env` e `/tmp/identity-pending-ci-final.log`. Hosts e navegadores temporários encerrados.

As ações com credenciais foram exercitadas apenas em ambientes isolados. O domínio público foi validado sem submissão. Páginas já abertas devem ser atualizadas para carregar a nova interface. Este relatório documenta a release e não exige nova publicação de binários; o plano temporário é encerrado após sincronizar esta documentação.
