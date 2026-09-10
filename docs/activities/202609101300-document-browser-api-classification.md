# Documentação da classificação de navegador, API e Playwright

Solicitação: registrar uma referência reutilizável para a escolha entre erro HTML e resposta de API, evitando redescobrir o comportamento em cada implementação.

Criado [USAGE-BROWSER-API-CLASSIFICATION](../networking/USAGE-BROWSER-API-CLASSIFICATION.md), com algoritmo exato de cabeçalhos, listas de métodos/rotas, distinção entre autorização e rate limit, matriz de exemplos, Playwright, idiomas, restrições de segurança e fontes/testes. Explicitado que não existe identificação confiável de pessoa ou automação: o helper escolhe apresentação conforme o pedido, sem conceder autorização ou alterar cotas.

Referências adicionadas ao índice de documentação do Identity, ao guia de rate limit e ao README do Sufficit Standard. Código de runtime e produção não foram alterados.

Validação: leitura dos classificadores e renderizadores atuais; links locais resolvidos em disco; todas as 12 rotas do 429 conferidas com o código; referências cruzadas dos índices conferidas; git diff --check. Não foi necessário executar a suíte de runtime para esta alteração exclusivamente documental.
