# Plano — módulo visual do Vault

**Status:** concluído e validado
**Criado:** 2026-08-08
**Módulo:** `Sufficit.Identity.UI.Vault`

## Objetivo

Entregar uma superfície Blazor reutilizável para o Vault do Sufficit Identity,
com `/vault` para o usuário final e `/vault/admin` para operadores. O endereço
legado `/management/vault` permanece como alias quando não houver conflito com
uma Management UI montada em `/management`. A UI
deve chamar contratos de aplicação, nunca `DbContext`, `IKeyVault` ou
`IVaultNamedSecretStore` diretamente.

## Limites de segurança

- O usuário final opera somente segredos vinculados ao próprio `subject` e ao
  namespace autorizado; não pode escolher ou enumerar nomes globais.
- O administrador acessa apenas metadados e operações permitidas pelas
  capabilities `identity.vault.secrets.read` e
  `identity.vault.secrets.manage`.
- Valores nunca aparecem em listagens, respostas GET ou auditoria.
- Revelação de valor não fará parte da primeira entrega; rotação/substituição é
  a operação segura padrão.
- Clientes e componentes não devem receber chaves de criptografia ou
  connection strings.

## Entregas

- [x] Extrair componentes visuais comuns para um RCL compartilhado.
- [x] Criar contratos de segredo pessoal com ownership/namespace.
- [x] Implementar persistência e autorização do cofre pessoal.
- [x] Criar o projeto `Sufficit.Identity.UI.Vault` e as rotas `/vault` e
  `/vault/admin`, preservando `/management/vault` como alias legado.
- [x] Integrar composição, assets e opções de hosting no servidor.
- [x] Cobrir testes de isolamento, capabilities, API, navegação e responsivo.
- [x] Registrar atividade concluída, executar build/suíte e publicar na `main`.

## Modelo inicial

O armazenamento global administrativo existente permanece compatível. Segredos
pessoais usam uma identidade composta por `owner_subject`, `namespace` e
`name`, com índice único nessa combinação. O namespace é validado no serviço,
não na rota, e a ausência de ownership nunca concede acesso ao usuário final.

## Critério de conclusão

Um usuário autenticado consegue criar, substituir e excluir apenas seus próprios
segredos permitidos; um operador consegue administrar os metadados globais com
capability explícita; nenhuma tela ou endpoint retorna plaintext; e o módulo
pode ser ativado/desativado sem quebrar as demais superfícies.

## Validação executada

- `dotnet build src/server/Sufficit.Identity.Server.csproj --no-restore`
- `dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore`
  — 532 testes (531 aprovados, incluindo isolamento e composição mobile),
  1 teste de localização ignorado por regra existente.
- Auditoria visual Impeccable no RCL e no Vault UI — nenhum antipadrão detectado.
