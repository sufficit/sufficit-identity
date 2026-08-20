# Ativação de mTLS no Eveo

O mTLS do Identity é ativado em uma porta dedicada para não alterar o fluxo
OIDC existente:

- `https://identity.sufficit.com.br:443` continua normal;
- `https://identity.sufficit.com.br:26501` continua sendo o endpoint de
  serviço/health atual;
- `https://identity.sufficit.com.br:26502` solicita certificado somente nos
  aliases RFC 8705, como `/connect/token/mtls`;
- o Nginx encaminha esses aliases para `127.0.0.1:26504`, e o Identity aceita
  o certificado apenas do peer local (`127.0.0.1/32`).

O Nginx usa `optional_no_ca` de propósito: certificados
`self_signed_tls_client_auth` não podem depender da confiança global do Nginx.
O Identity faz o vínculo exato do certificado público com o cliente e, quando
uma CA pública é configurada, valida também a cadeia PKI e a revogação.

## Configuração

O overlay versionado está em
[`deploy/mtls/mtls.eveo-apps.overlay.json`](../../deploy/mtls/mtls.eveo-apps.overlay.json).
Ele deve ser mesclado no `appsettings.eveo-apps.json` do host; não substitua o
arquivo inteiro, pois ele pode conter outras configurações específicas do
servidor. O drop-in do Nginx é
[`helpers/nginx-identity-mtls.conf`](../../helpers/nginx-identity-mtls.conf).

Depois de instalar ambos:

```bash
nginx -t
systemctl reload nginx
/opt/sufficit-identity/helpers/activate-release.sh --current
```

O restart é necessário porque a porta `127.0.0.1:26504` pertence ao processo
Kestrel e é carregada pela configuração da aplicação.

## Provisionar um cliente

1. Gere um certificado de cliente com `digitalSignature` e EKU
   `clientAuth`.
2. Em Management → Clients, abra o cliente confidencial e registre o
   certificado público no método `self_signed_tls_client_auth`.
3. Distribua o certificado e a chave privada somente para esse cliente. A
   chave privada nunca é enviada ao Identity.
4. Use o alias `token_endpoint` publicado em
   `/.well-known/openid-configuration`; no Eveo ele será
   `https://identity.sufficit.com.br:26502/connect/token/mtls`.

Sem um certificado no handshake, o Nginx retorna `400`. Com certificado não
registrado ou vinculado a outro cliente, o endpoint rejeita a autenticação; o
certificado por si só não concede acesso.

## PKI (`tls_client_auth`)

Para habilitar `tls_client_auth`, instale no host apenas o PEM público da CA
raiz/intermediária e adicione seu caminho em
`Mtls:TrustedCertificateAuthorityPaths`. O arquivo não pode conter chave
privada. O certificado folha continua sendo registrado no cliente; a CA não
substitui o vínculo por cliente.

Faça a rotação mantendo temporariamente os dois certificados registrados,
valide o novo certificado e remova o antigo depois da janela de propagação.
