# RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **A — Completa** |
| Origem | OpenIddict (parâmetro), próprio (anúncio) |
| Spec | https://www.rfc-editor.org/rfc/rfc9207 |

## Como está implementado

O OpenIddict anexa `iss` a toda resposta de autorização redirecionável. O
repositório acrescenta o bit de capacidade correspondente ao documento de
discovery, incondicionalmente:

```
context.Metadata["authorization_response_iss_parameter_supported"] =
    JsonValue.Create(true);
```

`src/sts/OpenIddictServerConfiguration.cs:567-570`.

## Por que importa

Sem `iss`, um cliente que fala com vários AS pode ser induzido a enviar um código
de autorização emitido pelo AS A para o endpoint de token do AS B — o ataque de
mix-up do RFC 9700 §4.4. Com `iss` na resposta e o cliente comparando com o
issuer registrado, o ataque falha.

A especificação de autorização do MCP exige que o AS que emite `iss` **também**
anuncie `authorization_response_iss_parameter_supported: true`; um cliente MCP
rejeita a resposta se o metadado disser `true` e o `iss` vier ausente. Como aqui
o valor é sempre `true` e o OpenIddict sempre anexa, as duas pontas batem.

## Dependência

O valor de `iss` emitido é o issuer efetivo. Se `Sufficit:Identity:Issuer`
estiver vazio, o OpenIddict deriva do `Host` da requisição — e então o `iss`
segue um cabeçalho que pode ter sido forjado, esvaziando a proteção.
**Configurar o issuer em produção não é opcional.**

## Testes

`DiscoveryTests`, `AuthorizationCodeFlowTests`.
