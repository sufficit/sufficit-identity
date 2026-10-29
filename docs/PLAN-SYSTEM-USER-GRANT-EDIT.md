# Edição do grant nativo de usuários de sistema
1. CONCLUÍDO: regressão HTTP e validação compartilhada; corrigir reconhecimento e permissões derivadas.
2. CONCLUÍDO: testes/build, documentação, commit e push main.
3. CONCLUÍDO: atualizar MySqlConnector vulnerável que bloqueou o CI; validar e publicar a correção.
4. CONCLUÍDO: publicar cluster pelo runbook e validar revisão/saúde uniforme.
5. EM ANDAMENTO — BLOQUEADO POR CREDENCIAL EXPIRADA: recuperar acesso MCP com novo token temporário e verificar.
Contrato: somente grant nativo conhecido; grants desconhecidos e limites de origem permanecem recusados.
Validação: teste falha antes/passa depois; suíte existente; saúde/revisão uniforme dos nós.

Commit 31c5ec9 na main; CI remoto 40899604965 bloqueado por NU1902 (MySqlConnector 2.5.0). Pacote preparado, não ativado. Advisory GHSA-473q-m89c-ghf8 corrigido a partir de 2.6.1; pin 2.6.2.

MySqlConnector 2.6.2: build Release -warnaserror sem avisos/erros; 1932 testes passaram, 2 skips preexistentes.

Produção bfaf3415b1ffc01a956316b60754fe5228a7c543: dois nós ativos, health/ready Healthy, certificados e JWKS uniformes. CI 40900832978 e CodeQL 40900833197 passaram. Token temporário retornou HTTP 401; scope não alterado.
