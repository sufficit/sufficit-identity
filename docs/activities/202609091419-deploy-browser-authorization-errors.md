# Publicação da recuperação de erros de autenticação

Autorizado commit, push e deploy dos dois projetos. Identity `main` publicado no commit `b8545d37b68ab27970e7d9d9be0ee8e8765912d7`; merge inclui a alteração inicial `1b93ca3` e as mudanças concorrentes de `f7a1720`, sem force push.

## Integração

- Preservada a correção de replay de device-code do remoto.
- Classificador `BrowserNavigationRequest` compartilhado: apresentação HTML apenas para GET interativo com Accept adequado e Fetch Metadata de documento, quando presentes. Não é decisão de autorização.
- Renderer SSR da UI e renderer STS sem UI são mutuamente exclusivos via status-pages feature.
- Recursos de texto pt-BR/en conforme padrão do projeto; removido link Blazor fixo da UI genérica. Ação segura retorna ao início do Identity; usuário reinicia o acesso no aplicativo de origem.
- 1103 testes locais aprovados, zero warnings, SUI em modo pacote. CI/secret scanning e CodeQL aprovados, runs 34381502637 e 34381502717.

## Deploy e evidência

Eveo, Apoint e Castrum já operavam com diretório convencional `/opt/sufficit-identity`, não symlink. Publicação pelo `deploy.py` oficial da raiz, sequência Eveo → Apoint → Castrum, usando o mesmo artefato `publish-net10.0-20260909141255`. Nenhuma migração, alteração de configuração ou rotação de certificado.

Em todos os nós:

- Health/ready saudáveis; serviço ativo, NRestarts=0.
- SHA-256 Server.dll: `a843c59d4cd743e5e4d237874287c6732eca8d37ea9de54549fce7f2684c05a1`.
- SHA-256 UI.dll: `89d3731db7296d3dc0fc121e625237e89626068957ce3869233c3c3260698b52`.
- SHA-256 STS.dll: `a0c9e1ad5abd50df076e258b0b1a4b1f5173b55b232e61503c355cfe834b84bf`.
- Erro authorize para navegação HTML: 400 text/html com recuperação; requisição técnica: 400 text/plain; CSS 200.
- Configurações e certificados comparados byte a byte com o backup e preservados.
- Backup independente 0600: `/opt/sufficit-auth-rollback-20260909T1715Z.tar.gz`. O `.prev` do swap foi removido pelo script; rollback permanece disponível no tar.

Config source_folder temporário restaurado após reutilizar o artefato; árvore limpa antes da documentação final. Blazor publicado em conjunto, versão `1.26.0909.1711+4f8dbd6`. Sem manipular tokens/contas reais. Relatório detalhado em sufficit-blazor/docs/activities/202609091419-deploy-authentication-guidance.md.
