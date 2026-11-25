# Visualização de segredos pessoais no Vault

## Entrega

Em **Segredos adicionados por você**, selecione **Visualizar** ao lado do
segredo. Na primeira visualização, confirme o código atual do app autenticador.
A autorização é válida por 15 minutos na mesma sessão do navegador e cada
leitura exibe somente o item selecionado. O diálogo limpa o valor ao fechar ou
expirar. Se o autenticador ainda não estiver configurado, o diálogo abre o
caminho para a configuração da conta.

O servidor exige o cookie de sessão e valida o token antifalsificação no POST.
A autorização protegida está vinculada ao usuário, ao identificador da sessão
e ao carimbo de segurança. O prazo é fixo e a resposta tem `Cache-Control:
no-store`. Tentativas inválidas usam o limite persistido do ASP.NET Core
Identity. A decriptação usa o armazenamento existente e o namespace pessoal do
usuário. O fluxo da tela só atende aos segredos pessoais. O modo autônomo do
Vault também serve o script do Blazor exigido pelos botões interativos.

A captura e a [avaliação de adoção do SUI](../frontend/EVALUATION-SUI-ADOPTION.md)
orientaram a posição do botão e o uso dos controles existentes. O formulário da
conta orientou os textos do autenticador. A interface tem recursos em português
e inglês. A referência anti-AI-slop do Refero orientou o uso de um único diálogo,
sem introduzir novas superfícies na lista.

## Validação

- Restore em modo bloqueado (lockfile) e build Release de 18 projetos com warnings
  tratados como erros. Imagem Docker construída localmente.
- 2.187 testes aprovados na suíte principal.
  O teste de integração do Vault cobre o código inválido, a validação
  antifalsificação, o prazo fixo, o isolamento por sessão/usuário e o namespace.
- Chromium local com dados fictícios em 390 e 1.440 pixels. Foram verificados
  o desafio, a exibição, a limpeza ao fechar e ao expirar e o reaproveitamento
  da autorização. Os dois testes da cadeia MFA também passaram.
- Schema canônico e scripts aditivos exercitados no MariaDB 10.4.34 isolado.
  Host somente API, checksums do Pomelo, propagação de lockfiles, JavaScript,
  auditoria NuGet e varredura de segredos verificados.
- Removido do índice o link para o plano anterior de adição de escopo OAuth,
  cujo encerramento já tinha uma atividade vinculada.

## Publicação em produção

O [runbook de publicação gradual](../runbooks/RUNBOOK-CLUSTER-ROLLING-DEPLOY.md)
ativou a release `20261125T132053Z-f7533ad` nos três nós, um de cada vez. A
revisão é `f7533ad4487a7e01e8d3a17148bb11abd9041a86` e o SHA-256 do artefato
é `8c0e09a16bc006e425fe62d79678599b6c7f256caf00a9e3bff40ecefdfbb1c8`.
O preparo verificou o mesmo artefato em cada nó e herdou quatro arquivos de
configuração da release anterior `20261124T152335Z-cc3a967`. A revisão
dispensou migração de banco.

Os três serviços ficaram ativos na revisão esperada, com liveness e readiness
saudáveis e os mesmos hashes de certificado e JWKS da verificação anterior.
As sondas diretas observaram respostas HTTP 502 durante as reinicializações e
todos os nós se recuperaram no prazo do wrapper.

No endereço público, saúde, prontidão e descoberta OIDC responderam HTTP 200.
O POST sem sessão em `/vault/reveal` passou de HTTP 404 antes da ativação a
HTTP 302 para a página de login, e o JavaScript do Vault servido em produção
coincidiu byte a byte com o código publicado. A validação autenticada com
código TOTP e leitura de segredo usou dados fictícios no ambiente local.
