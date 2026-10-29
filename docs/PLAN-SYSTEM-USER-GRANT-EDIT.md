# Edição do grant nativo de usuários de sistema
1. CONCLUÍDO: regressão HTTP e validação compartilhada; corrigir reconhecimento e permissões derivadas.
2. CONCLUÍDO: testes/build, documentação, commit e push main.
3. CONCLUÍDO: atualizar MySqlConnector vulnerável que bloqueou o CI; validar e publicar a correção.
4. EM ANDAMENTO: publicar cluster pelo runbook; recuperar acesso MCP com token válido e verificar.
Contrato: somente grant nativo conhecido; grants desconhecidos e limites de origem permanecem recusados.
Validação: teste falha antes/passa depois; suíte existente; saúde/revisão uniforme dos nós.

Commit 31c5ec9 na main; CI remoto 40899604965 bloqueado por NU1902 (MySqlConnector 2.5.0). Pacote preparado, não ativado. Advisory GHSA-473q-m89c-ghf8 corrigido a partir de 2.6.1; pin 2.6.2.

MySqlConnector 2.6.2: build Release -warnaserror sem avisos/erros; 1932 testes passaram, 2 skips preexistentes.
