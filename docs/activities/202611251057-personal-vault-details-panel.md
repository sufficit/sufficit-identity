# Painel de detalhes do Vault pessoal

A proposta aprovada reúne o aviso **Visualização protegida**, a busca e os
filtros à esquerda e o detalhe do segredo à direita. Em telas estreitas, as
seções se empilham e selecionar uma linha leva o foco ao detalhe. Os botões,
cartões, chips, badges, ícones e campos usam Sufficit.Blazor.UI, seguindo o
[sistema visual](../design/DESIGN-SYSTEM.md) e os
[padrões de adoção](../frontend/EVALUATION-SUI-ADOPTION.md).

O nome armazenado identifica o segredo. O último segmento do caminho sugere
o tipo para os chips e filtros. Caminhos sem convenção reconhecida aparecem
como **Segredo**. A busca filtra nomes, enquanto a seleção mostra o caminho
e a última atualização. **Adicionar segredo** abre o formulário. O menu do
item permite substituir o valor ou remover o segredo com confirmação. As
credenciais de aplicativos ficam em um cartão expansível com status e
orientação, e o acesso administrativo segue sua política.

A máscara do painel é decorativa. **Visualizar segredo** abre o diálogo
autenticado do [fluxo 2FA publicado](202611250956-personal-vault-reveal.md).
A autorização vale por 15 minutos na mesma sessão.

## Validação

- Build Release de 18 projetos com warnings tratados como erros, restore
  em modo bloqueado e imagem Docker local.
- Suíte principal com 2.187 testes aprovados. Após o ajuste de tipografia,
  122 testes de Vault e documentação e dois testes da cadeia MFA passaram.
- Chromium em 1.440 e 390 pixels, com segredos fictícios. Foram verificados
  busca, filtros, seleção por teclado e foco, credenciais conectadas,
  cadastro, substituição, remoção, o desafio TOTP e o reaproveitamento da
  autorização. Capturas em português verificadas visualmente.
- Checksums do Pomelo, propagação de lockfiles, cobertura de migrações SQL
  e auditoria de dependências verificados.

## Publicação em produção

A release `20261125T135939Z-facea97` foi ativada em sequência nos três nós
pelo [runbook de publicação gradual](../runbooks/RUNBOOK-CLUSTER-ROLLING-DEPLOY.md).
A revisão publicada é `facea979561b65233de2a483771c809772ea7043` e o SHA-256
do pacote é `c94dc1df507fea63d69d0bb4725c55d3d378389220050fb499b6a1ac44a701bc`.
O preparo verificou o mesmo pacote em cada nó e herdou quatro arquivos de
configuração da release anterior `20261125T132053Z-f7533ad`. A revisão
dispensou migração de banco.

Cada nó reportou o serviço ativo e saudável, com a revisão esperada e os
mesmos hashes de certificado e JWKS da checagem inicial. As sondas diretas
observaram HTTP 502 durante as reinicializações e os nós se recuperaram no
prazo do wrapper.

No endereço público, saúde, prontidão e descoberta OIDC responderam HTTP 200.
O CSS servido coincide byte a byte com a revisão publicada. O GET de
`/vault` e o POST de `/vault/reveal` sem sessão redirecionaram para o login.
A navegação autenticada e a visualização com TOTP foram verificadas em
Chromium com dados fictícios no ambiente local.
