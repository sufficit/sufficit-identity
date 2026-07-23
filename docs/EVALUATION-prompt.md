Faça uma avaliação e comparação completa e independente do projeto
/mnt/sufficit/sufficit-identity (STS OAuth 2.0/OIDC em .NET, OpenIddict,
ASP.NET Core Identity, MySQL). Não assuma nada de antemão — investigue o
código do zero, como se fosse a primeira vez que o vê.

1. RECONHECIMENTO — mapeie a arquitetura sozinho: projetos, dependências,
   fluxo de dados, schema de banco, endpoints expostos, superfície de
   configuração. Leia o código-fonte inteiro, não resuma por nomes de arquivo.

2. VULNERABILIDADES — audite ativamente por conta própria: autenticação e
   fluxos OAuth/OIDC (grants habilitados, PKCE, redirect_uri, emissão e
   validação de tokens, claims vazadas ou faltando), gestão de segredos e
   certificados, brute-force/lockout/rate limiting, injeção, autorização
   quebrada, exposição de dados sensíveis, configuração insegura por default,
   dependências desatualizadas ou com CVEs conhecidas, superfície de ataque
   dos endpoints /connect/*. Classifique cada achado por severidade com
   cenário de exploração concreto.

3. COMPARAÇÃO DE MERCADO — pesquise na web o estado atual (mais recente
   possível) de concorrentes diretos: Keycloak, Duende IdentityServer,
   OpenIddict puro, Zitadel, Ory (Hydra/Kratos), Authentik, Authelia,
   Auth0/Okta, Microsoft Entra ID, e qualquer player relevante que surgir
   na pesquisa. Compare versões, licenciamento, arquitetura, cobertura de
   protocolo, postura de segurança padrão, e o que hoje é considerado
   baseline "moderno" para um STS (passkeys, OAuth 2.1, FAPI 2.0, DPoP,
   token exchange RFC 8693, SSF/CAEP, autorização para agentes de IA/MCP).

4. PONTUAÇÃO — dê uma nota de 0 a 10 por dimensão (segurança, arquitetura,
   qualidade de código, completude de protocolo, prontidão para produção)
   e uma nota geral, com justificativa objetiva para cada uma. Posicione
   o projeto no ranking frente aos concorrentes pesquisados.

5. VEREDITO — conclusão direta: pontos fortes, riscos que bloqueiam uso em
   produção, e se você recomendaria adotar este software hoje.

Trabalhe com autonomia total: pode rodar comandos, ler qualquer arquivo do
repositório, pesquisar na web, e usar agentes em paralelo para acelerar a
investigação e a pesquisa de mercado. Não pergunte antes de agir — decida e
execute.

Salve o resultado em /mnt/sufficit/sufficit-identity/docs/eval/EVALUATION-<data>-<nome-do-modelo>.md
(nome do modelo usado nesta avaliação no nome do arquivo). Não faça commit
de nada.