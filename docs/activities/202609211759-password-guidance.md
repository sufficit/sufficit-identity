# Alteração de senha e requisitos claros

## Objetivo e diagnóstico

Corrigir a dificuldade de alteração de senha reportada pelo usuário e explicar as exigências em linguagem simples nas telas que recebem uma senha nova. A tarefa continuou o fluxo de entrega já autorizado de commit, push, merge e deploy.

A árvore começou limpa em `main`, com a publicação anterior `68754ce` nos três nós. A leitura restrita às opções de senha e às respectivas variáveis de ambiente confirmou a mesma política em eveo-apps, apoint-apps e castrum-apps: mínimo 12, maiúscula, minúscula, número, símbolo e 4 caracteres distintos; rejeição de senhas conhecidas em vazamentos habilitada, com LocalFallback.

O defeito funcional foi reproduzido antes da correção: ChangePassword e ResetPassword usam POST estático, mas os campos de senha não tinham `name`. Mesmo preenchidos, não faziam parte do FormData; o servidor recebia somente os campos ocultos e retornava validação de obrigatório. A alteração ainda mostrava mensagens em inglês. As páginas não explicavam os requisitos; a redefinição continha mínimo 6 fixo, divergente do runtime.

## Alterações e decisões

- **Envio:** acrescentados os nomes de binding aos campos de alteração/redefinição, preservando POST estático e antiforgery. Após sucesso na alteração, os campos são limpos.
- **Política:** contrato neutro `AccountPasswordPolicy` e provider que projeta as opções efetivas do Identity para a UI. A política de segurança não foi alterada.
- **Instruções:** componente compartilhado junto ao campo de senha, em cadastro, redefinição e alteração. Mostra comprimento, exemplos de maiúsculas/minúsculas/número/símbolo e a restrição de senhas expostas. Regras vêm do runtime; o limite de 100 já existente em cadastro/redefinição permanece explícito. Quatro categorias diferentes já garantem quatro caracteres distintos; uma linha de unicidade aparece quando a configuração exige mais.
- **Feedback:** erros traduzidos por código, incluindo senha atual incorreta, confirmação divergente, complexidade, senha exposta e indisponibilidade da consulta. Resumos visíveis e mensagens localizadas de validação. A continuação do cadastro repetido por login permanece sem aplicar regras de senha nova ao acesso existente.
- **Referências:** telas atuais/SUI como direção principal; Refero copywriting para condições e próximo passo, exemplos concretos e frases curtas; Sufficit Frontend para integração e validação. Layout, tokens e componentes existentes preservados. Texto de ajuda ligado ao campo por `aria-describedby`.

## Validação

- 134 testes direcionados aprovados, zero avisos: formulários, self-service, revogação na redefinição, fronteiras públicas, continuação de cadastro, localização, arquitetura, senhas expostas e contratos de tamanho.
- Dez testes novos exercitam GET/POST dos componentes reais com ASP.NET Identity e SQLite: sucesso, senha curta, falta de símbolo, confirmação divergente, senha atual incorreta, preservação/alteração efetiva da senha e política personalizada. Os campos enviados são extraídos do HTML, evitando que um POST montado manualmente esconda a falha original.
- Esses dez testes também passaram em checkout isolado com o NuGet fixado no CI. O parser HTML do teste foi corrigido para ignorar caixa nos nomes de atributos: o pacote antigo encaminha `Name`, e o SUI local emite `name`; ambos são equivalentes para o navegador. A exigência de existência dos campos permanece. O checkout foi removido.
- Playwright em host temporário: formulários com e sem JavaScript, pt-BR/en-US, desktop 1440 px e mobile 390 px; erros/sucesso, campos limpos e associação acessível conferidos, sem overflow. Screenshots inspecionadas. A cascata de autenticação também foi verificada sem registro adicional no harness, como na composição de produção.
- O harness com JS encontrou erro de decodificação de assets comprimidos, confirmado por curl; a rodada local serviu os dois scripts originais por interceptação. Os testes HTTP/SQLite e sem JS não dependem desse contorno. A rodada pública usou os assets reais, sem interceptação.
- `git diff --check`, restore locked em modo pacote e publicação Release com `-warnaserror` aprovados. Lockfiles gerados pelo uso do SUI local foram restaurados às versões aprovadas no CI.
- [CI final do PR](https://github.com/sufficit/sufficit-identity/actions/runs/35653174619): **1.593 aprovados, 1 ignorado, zero falhas**. Compilação com avisos como erros, contêiner, ensaios SQL, API-only, gitleaks e auditoria de dependências aprovados; nenhum advisory High/Critical.
- [CodeQL do PR](https://github.com/sufficit/sufficit-identity/actions/runs/35653174522), [CI do merge](https://github.com/sufficit/sufficit-identity/actions/runs/35653755517) e [CodeQL do merge](https://github.com/sufficit/sufficit-identity/actions/runs/35653755244) aprovados. CI do merge repetiu os mesmos totais.

O gitleaks inicialmente interpretou um identificador de opções como senha de banco. A variável local foi renomeada e o único commit funcional da branch foi corrigido com force-with-lease preso ao SHA anterior; nenhuma regra do scanner foi afrouxada. A primeira compilação também identificou conversão nullable de LocalizedString, corrigida com acesso explícito a Value.

## Entrega

[PR #80](https://github.com/sufficit/sufficit-identity/pull/80), commits `629125c` e `b088ef5`, integrado em `e9c11d182dce5eee2d1605ad0445377b1f255ac3`.

```sh
rtk dotnet publish src/server/Sufficit.Identity.Server.csproj -c Release -o publish-password-guidance -warnaserror
```

- Release: `20260921T205322Z-e9c11d1`.
- SUI local limpo: `cf71a685cedf1cf5e2e8f1dd0136fb571acbc38b`.
- SHA-256 do arquivo: `76e53f224fcb7b992c35c267ae8a9b9deedac0cb5dfe4f9535af8495071e2318`.
- Proveniência em `release-source.json` e integridade dos 337 arquivos em `release-files.sha256`.
- Migrator executado uma vez em eveo-apps antes da troca: Result=success, ExecMainStatus=0. Nenhuma migration nova nesta entrega.
- Ativação sequencial pelo helper com trava e rollback; configurações, helpers e certificados persistentes preservados. O script genérico não foi utilizado, conforme o runbook de ativação serializada.

A primeira ativação de eveo atingiu saúde e passou a checagem de conteúdo, mas uma asserção de CSS procurava o seletor no arquivo principal, que contém imports. O script fez rollback saudável para a versão anterior. Confirmado o estilo no bundle importado, a checagem foi corrigida para seguir o import e comparar o conteúdo com o artefato. A mesma release foi reativada e aprovada, sem mudança de código ou binários. Apoint e castrum foram atualizados em seguida, após o sucesso do nó anterior. Os 502 durante a inicialização terminaram dentro da espera normal de saúde.

| Nó | Release | Estado final |
| --- | --- | --- |
| eveo-apps | `20260921T205322Z-e9c11d1` | active/running, Healthy, 0 reinícios automáticos |
| apoint-apps | `20260921T205322Z-e9c11d1` | active/running, Healthy, 0 reinícios automáticos |
| castrum-apps | `20260921T205322Z-e9c11d1` | active/running, Healthy, 0 reinícios automáticos |

Em cada nó: liveness/readiness, discovery, mesmos dois kid OIDC, conteúdo de requisitos, CSS importado e JS aprovados. Artefato e arquivos persistentes conferidos. Nenhum evento de nível error no journal do serviço desde o início do rollout até a última verificação. A release anterior permanece disponível.

O domínio público retornou Healthy. Playwright confirmou as novas instruções e o CSS efetivamente carregado, associação ao campo, reCAPTCHA visível, cadastro hidratado e continuidade do login anterior, sem overflow mobile nem exceções JavaScript. Screenshot público inspecionado.

## Evidências e limites

Evidências temporárias em `/tmp/identity-password-review/` (baseline, roteiros, capturas desktop/mobile), `/tmp/identity-password-public-smoke.cjs`, `/tmp/identity-password-public-register.png`, `/tmp/identity-password-public-login.png` e `/tmp/identity-password-deploy.json`. Processos e navegadores temporários encerrados.

Nenhuma senha ou conta de cliente real foi alterada, e nenhum e-mail foi enviado. Alteração/redefinição com credenciais foram verificadas em ambientes isolados; a validação pública foi de navegação e implantação. Páginas que estavam abertas antes da publicação devem ser recarregadas para receber os campos corrigidos.

Este relatório complementa documentalmente a release executável; não exige nova publicação de binários. O plano temporário é encerrado com suas evidências preservadas aqui, sem referências externas pendentes.
