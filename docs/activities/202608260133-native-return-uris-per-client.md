# 2026-08-26 — Retorno nativo vira registro por cliente

## Problema

O serviço de identidade é genérico: qualquer empresa pode subir sua própria
instância. Mesmo assim, o retorno nativo do Device Authorization Grant estava
gravado no código — `DeviceAuthorizationReturnTargets` continha
`sufficit-genius://auth-complete` e `sufficit-aigenius://auth-complete`, e
qualquer cliente do servidor era aceito nesses endereços. Outros pontos
carregavam a mesma marca: `client_name` fixo na registration dinâmica, o
allowlist `Mcp.ImplicitClientIds` com valor embutido, a string
`Device.ReturnToGenius` na tela terminal e o `client_id` do seeder de testes.

## Entrega

- `DeviceAuthorizationReturnTargets` removido. No lugar,
  `NativeReturnUriPolicy` valida **forma** (esquema explícito, sem fragmento,
  sem esquema executável, `http` só em loopback, limites de tamanho e
  quantidade) e nunca cita um aplicativo.
- Quais endereços valem passou a ser dado de registro do cliente, gravado como
  metadata de extensão `native_return_uris` (RFC 7591 §2) no property bag da
  aplicação OpenIddict. A comparação é exata (RFC 8252 §8.1); esquema de uso
  privado é aceito porque RFC 8252 §7.1 é justamente esse mecanismo.
- Configuração pela Management API (`nativeReturnUris` em `POST`/`PUT
  /api/clients`), pela tela *Destinos e logout* da UI de gestão e por manifesto
  de provisionamento.
- A página terminal não recebe mais `return_uri` cru: o STS resolve contra o
  registro do cliente e entrega um `return_ticket` protegido (10 min). A tela de
  resultado, que não tem mais a transação para consultar, apenas abre o ticket.
- Broker de integrações resolve o callback contra o cliente do token
  apresentado; sem registro responde `400 return_uri_not_registered`. O ticket
  criptografado passou a carregar o retorno, então o caso "pending expirado"
  não depende mais de um endereço embutido.
- `client_name` da registration dinâmica vem do display name do cliente
  chamador; `Mcp.ImplicitClientIds` não tem mais default; `Device.ReturnToApp`
  substituiu `Device.ReturnToGenius`; seeder de testes usa
  `test-device-client`/`test-ropc` com callbacks próprios.

## Migração

O cliente `sufficit-ai-genius` já implantado precisa registrar seus dois
callbacks (`PUT /api/clients/sufficit-ai-genius` com `nativeReturnUris`) e o
`appsettings.json` de produção — que não é versionado — precisa manter
`Sufficit:Identity:Mcp:ImplicitClientIds` com `sufficit-ai-genius`. O template
do repositório agora vem com a lista vazia, porque é o arquivo que qualquer
empresa copia. Detalhes em
[ARCHITECTURE-NATIVE-RETURN-URIS](../architecture/ARCHITECTURE-NATIVE-RETURN-URIS.md).

## Verificação

`dotnet test src/tests/Sufficit.Identity.Tests.csproj` — 892 testes, 0 falhas.
Cobrem a política (aceite, recusa por esquema/fragmento/tamanho, match exato),
o round-trip da Management API, a propagação do ticket no device flow e a recusa
de um callback que o cliente não registrou.
