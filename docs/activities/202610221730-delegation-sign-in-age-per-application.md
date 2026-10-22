# Idade do login para delegação, por aplicação

**22/10/2026.** O limite de quão recente o login do usuário precisa ser para
uma aplicação delegar uma credencial (`auth_time` do token de origem) era só
do servidor (`TokenExchange:DelegatedCredentials:MaxAuthAgeHours`). Agora cada
aplicação delegante pode ter o seu, nas configurações do próprio cliente
(`sufficit:delegation_max_auth_age_hours`, 1–168 h, os mesmos limites do
servidor). Sem valor na aplicação, vale o padrão do servidor.

- Decisão do dono: o identity é genérico e atende várias empresas; uma
  preferência de produto (quanto tempo um login vale para delegar) pertence à
  aplicação, não ao servidor nem a uma exceção que cite um produto.
- Emissor: `DelegatedCredentialIssuer` lê o valor do cliente que pede a
  delegação; `DelegationSignInAge` concentra chave, limites e leitura.
- Management: campo "Login para delegação" no editor do cliente (herdar o
  padrão ou definir em horas), exibido no detalhe; API `delegationMaxAuthAgeHours`
  e `clearDelegationMaxAuthAge`.
- Testes: um login de 3 h é recusado com o padrão de 1 h e aceito quando a
  aplicação define 168 h; criação fora dos limites recusada; limpar volta ao
  padrão.

O aviso de postura `delegated-credentials-stale-sign-in` continua olhando só o
padrão do servidor: um valor maior numa aplicação é decisão registrada dela,
auditada pelo Management.
