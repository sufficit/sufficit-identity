# OAuth Client ID Metadata Document (CIMD)

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **B — Substancial** |
| Origem | Próprio |
| Spec | `draft-ietf-oauth-client-id-metadata-document` (Internet-Draft) |

## O que é

Em vez de registrar o cliente antecipadamente, o `client_id` **é** uma URL HTTPS
que serve o próprio documento de metadados. O AS busca o documento na primeira
vez que vê aquele identificador. A especificação de autorização do MCP **depreca
o DCR** (RFC 7591) em favor deste mecanismo.

## Como está implementado

| Componente | Papel |
|---|---|
| `src/sts/Cimd/ClientIdMetadataResolver.cs` | Busca e valida o documento |
| `src/sts/Cimd/CimdApplicationProvisioner.cs` | Cria a aplicação no primeiro uso |

O gancho está no `/connect/authorize`: quando `FindByClientIdAsync` não encontra
o cliente, `TryProvisionAsync` é chamado antes de falhar
(`src/sts/Controllers/AuthorizationController.cs:176-190`). Identificador que não
tenha a forma de URL CIMD cai no erro normal de cliente desconhecido.

## Regras de busca e validação

`ClientIdMetadataResolver.cs:36-48`:

| Regra | Valor |
|---|---|
| Só `200 OK` | Redirecionamentos **não** são seguidos |
| Tamanho máximo da resposta | `Mcp:ClientIdMetadataDocuments:MaxDocumentBytes`, padrão 5120 |
| Timeout | `FetchTimeoutSeconds`, padrão 3, limitado a 30 |
| Cache | `CacheTtlSeconds`, padrão 300 |
| `client_id` do documento | Precisa ser **exatamente igual** ao identificador usado |
| `redirect_uris` | Validados pela mesma política dos demais clientes |
| Saída HTTP | Pelo guarda anti-SSRF |

Não seguir redirecionamento é o detalhe que impede um `client_id` aparentemente
externo de apontar, por desvio, para um documento interno.

## Cliente provisionado

Nasce como cliente público, com o perfil de cliente MCP, PKCE exigido e
consentimento explícito. `private_key_jwt` para clientes CIMD está marcado no
código como extensão futura (`CimdApplicationProvisioner.cs:20`).

## Anúncio

`client_id_metadata_document_supported` é publicado no documento de discovery
seguindo a flag `Mcp:ClientIdMetadataDocuments:Enabled`, que é `false` por padrão
(`src/sts/OpenIddictServerConfiguration.cs:572-577`, `src/sts/Options/McpOptions.cs:199`).

## Posição de mercado

O Keycloak só ganhou CIMD experimental na 26.6 (2026). Ter isto implementado e
anunciado corretamente é vantagem competitiva no cenário MCP.

## Lacunas

- Sem revalidação periódica do documento após o cache expirar para clientes já
  provisionados: o registro persistido é a fonte depois do primeiro uso.
- Sem `private_key_jwt` para cliente CIMD.

## Testes

`CimdTests`.
