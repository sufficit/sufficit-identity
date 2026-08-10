# Escopo autorizado para o Strix — Sufficit Identity

## Alvo

- `https://identity.sufficit.com.br`

## Objetivo

Avaliar de forma não destrutiva os fluxos públicos de identidade: OIDC/OAuth,
device authorization, login, consentimento, tokens, logout, recuperação de conta,
controle de acesso e headers de segurança.

## Restrições

- Não criar contas em massa nem enviar e-mails deliberadamente.
- Não alterar, excluir ou enumerar dados reais de usuários.
- Não testar endpoints de administração com credenciais reais sem autorização específica.
- Não executar denial of service, flooding, brute force ou exploração destrutiva.
- Não sair do domínio `identity.sufficit.com.br`.
- Não usar ferramentas de edição (`apply_patch`) nem tentar alterar código ou arquivos do alvo remoto.
- Registrar qualquer requisição autenticada e interromper ao primeiro efeito colateral.

## Focos do primeiro ciclo

- validação de `redirect_uri`, `state`, `nonce` e PKCE;
- emissão, escopo, audiência, expiração e revogação de tokens;
- device flow e polling, incluindo autorização repetida/expirada;
- consentimento e separação entre usuário, aplicação e políticas;
- CSRF, sessão, cookies e headers de segurança;
- rate limiting e mensagens de erro sem vazamento de dados.

## Compatibilidade do executor

Ao usar as ferramentas de proxy, omita argumentos opcionais (`after`, `scope_id`
e `parent_id`) quando não houver valor. Não envie a string literal `"null"`;
o Caido interpreta esse texto como cursor/ID e retorna `Invalid ID format` ou
`Failed to parse cursor`.
