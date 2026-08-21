# Credenciais e métodos de autenticação para clientes OAuth

## Decisão

O Sufficit Identity mantém um registro próprio de credenciais de clientes,
independente das entidades do OpenIddict. Uma aplicação pode ter:

- uma credencial compartilhada principal, mantida temporariamente no campo
  legado do OpenIddict;
- até cinco credenciais compartilhadas adicionais, com nome, início de
  validade, expiração e revogação independentes;
- até dez chaves públicas simultâneas em um JWKS embutido para
  `private_key_jwt`;
- até dez certificados públicos simultâneos para
  `self_signed_tls_client_auth` ou CAs subordinadas para `tls_client_auth`.

Várias credenciais podem permanecer ativas durante uma rotação. Em uma
requisição OAuth concreta, o cliente deve escolher exatamente um método de
autenticação. Combinar, por exemplo, `client_secret_post` e
`private_key_jwt` na mesma requisição é rejeitado.

## Base normativa

- RFC 6749, seção 2.3: o servidor pode estabelecer um conjunto de credenciais
  e aceitar métodos adequados às suas necessidades; o cliente não pode usar
  mais de um método de autenticação em uma requisição.
- RFC 7523: define a JWT bearer assertion usada por `private_key_jwt`.
- RFC 7591: a resposta de registro dinâmico possui um `client_secret`
  singular. A pluralidade interna não é metadado padronizado de DCR.
- RFC 7592: padroniza atualização e rotação do registro, mas não define um
  array interoperável de segredos sobrepostos.
- RFC 8705: define autenticação e sender constraint por certificado mTLS.
- RFC 9700: recomenda autenticação assimétrica de clientes quando possível,
  preferindo `private_key_jwt` ou mTLS a segredos compartilhados.

Múltiplos segredos ativos são, portanto, uma extensão operacional do servidor
para rotação sem indisponibilidade. Ela não altera o formato das requisições
OAuth nem cria um grant novo.

## Persistência e proteção

A tabela `oauthclientcredentials` usa o `client_id` imutável como vínculo e
não possui chave estrangeira para uma entidade do OpenIddict. Isso permite
substituir o motor OAuth sem migrar o ciclo de vida das credenciais.

O texto puro nunca é persistido. Segredos adicionais usam o formato versionado
do ASP.NET Core Identity com PBKDF2-HMAC-SHA512 e 210.000 iterações. A interface
recebe o valor completo apenas na resposta de criação e depois mostra somente
seis caracteres finais. O limite de cinco credenciais adicionais também limita
o trabalho de hashing por tentativa de autenticação.

Revogação e expiração são avaliadas no momento da autenticação. Alterações usam
concorrência otimista e todos os eventos administrativos são auditados sem o
valor da credencial.

## Métodos suportados

### Segredo compartilhado

Todas as credenciais compartilhadas ativas podem ser usadas com
`client_secret_basic` ou `client_secret_post`. Esses dois nomes representam
transportes alternativos do mesmo tipo de material; uma requisição escolhe um
deles.

A credencial principal preserva clientes existentes. Novas credenciais ficam
no registro próprio e o adaptador `SufficitOpenIddictApplicationManager`
consulta ambos durante a transição.

### `private_key_jwt`

A administração aceita somente JWKS público embutido. Material privado,
chaves simétricas, `kid` duplicado, RSA menor que 2048 bits, curvas fora de
P-256/P-384/P-521 e algoritmos incompatíveis são rejeitados. Várias chaves
públicas podem coexistir para rotação.

O campo `jwks_uri` existente continua reservado à resolução remota usada por
request objects/JAR. Ele não é anunciado como fonte de autenticação
`private_key_jwt`; para esse método, as chaves precisam estar no JWKS embutido
até que uma política remota equivalente seja implementada e testada.

### mTLS

Quando mTLS está habilitado no deployment, o STS ativa os validadores nativos
RFC 8705 do OpenIddict para `self_signed_tls_client_auth` e, quando existe uma
trust store explícita, para `tls_client_auth`. Os aliases, a autenticação do
cliente e o `cnf.x5t#S256` passam a formar uma única capacidade; o servidor não
trata mais a mera presença de um certificado como autenticação suficiente.

O método recomendado registra no JWKS da aplicação somente o certificado
autoassinado público, com `digitalSignature` e EKU `clientAuth`. A chave privada
permanece no cliente. Certificados sobrepostos permitem rotação; remover o JWK
revoga imediatamente novas autenticações. O modo PKI aceita no JWKS apenas CAs
subordinadas não autoemitidas com `keyCertSign`; raízes e intermediárias
confiáveis são arquivos públicos administrados pelo deployment.

A tela sempre permite preparar o material e informa separadamente se o
transporte mTLS do deployment e a trust store PKI estão ativos. Assim, cadastro
administrativo não é confundido com disponibilidade operacional do endpoint.

## API administrativa

- `GET /api/clients/{clientId}/credentials`: métodos e metadados, nunca hashes.
- `POST /api/clients/{clientId}/credentials`: cria uma credencial e retorna o
  valor uma única vez.
- `POST /api/clients/{clientId}/credentials/{credentialId}/revoke`: revoga uma
  credencial adicional com verificação de versão.
- `POST /api/clients/{clientId}/secret/rotate`: compatibilidade para substituir
  a credencial principal.
- `POST /api/clients/{clientId}/certificates`: registra certificado público ou
  CA subordinada, rejeitando material privado.
- `POST /api/clients/{clientId}/certificates/{keyId}/revoke`: remove o vínculo
  e impede novas autenticações com o certificado.
- `PUT /api/clients/{clientId}` com `jwksJson`: registra, gira ou remove chaves
  públicas de `private_key_jwt`.

## Saída futura do OpenIddict

O adaptador atual é deliberadamente estreito: ele sobrescreve somente a
validação de segredo e delega o restante do protocolo ao OpenIddict. O vínculo
mTLS é expresso como JWKS padrão, não como estrutura privada do handler. Na
troca do motor, a tabela, o hasher, os contratos administrativos, a auditoria,
a UI e o material público permanecem; muda apenas o adaptador que lê o JWKS e
valida o handshake. A etapa final será migrar a credencial principal para o
registro próprio e remover o caminho de compatibilidade.
