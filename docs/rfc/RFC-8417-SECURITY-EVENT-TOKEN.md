# RFC 8417, 8935 e 8936 — Security Event Token e sua entrega

| | |
|---|---|
| Papel | Transmissor de eventos de segurança |
| Abrangência | **B — Substancial** |
| Origem | Próprio |
| Specs | RFC 8417 (SET), RFC 8935 (push), RFC 8936 (poll) |

## Como está implementado

O SET é o envelope; o conteúdo semântico (CAEP, RISC) está descrito em
[SPEC-SSF-CAEP-RISC.md](SPEC-SSF-CAEP-RISC.md). Aqui trata-se do formato e da
entrega.

| Componente | Papel |
|---|---|
| `src/sts/SharedSignals/CaepEventGenerator.cs` | Monta e **assina** o SET |
| `src/sts/SharedSignals/SharedSignalsDispatcher.cs` | Decide push ou poll e entrega |
| `src/sts/SharedSignals/SsfStreamStore.cs` | Persiste streams e a fila de poll |
| `src/sts/Controllers/SsfPollController.cs` | Endpoint de pull |

## Formato do SET

`CaepEventGenerator` emite um JWT assinado com a credencial auxiliar, com `jti`
aleatório de 128 bits (`:312`) e `events` como mapa de URI de tipo para o
payload. As URIs usadas são as canônicas do OpenID:
`https://schemas.openid.net/secevent/caep/event-type/…` e
`…/risc/event-type/verification` (`:12-20`).

| Requisito RFC 8417 | § | Estado |
|---|---|---|
| `iss`, `iat`, `jti`, `aud` | 2.2 | Sim |
| `events` como objeto JSON | 2.2 | Sim |
| SET assinado (JWS) | 3 | Sim |
| `sub` fora do `events` desencorajado | 2.2 | Sim, o sujeito vai no payload do evento |
| SET cifrado (JWE) | 3 | Não |

## Entrega push (RFC 8935)

`DeliverPushStreamAsync` faz `POST` no endpoint configurado do receptor, com o
cabeçalho `Authorization` opcional do stream
(`SsfStreamsController.cs:104`). Entregas falhas são registradas, e uma falha de
receptor **não** desfaz a operação local que gerou o sinal — a chamada é feita
com prazo limitado e as exceções são absorvidas
(`AuthorizationController.Logout.cs`, bloco do `_sharedSignalsDispatcher`).

O endpoint de destino passa por `SafeHttpHandlerFactory.ValidateRequestUri`
(`SsfStreamStore.cs:181`), o que impede um operador de transformar o
transmissor em scanner de rede interna.

## Entrega poll (RFC 8936)

Streams de poll não recebem HTTP; o SET é enfileirado em `ssfsetdeliveries`
(`SharedSignalsDispatcher.cs:162-173`) e retirado pelo receptor via
`SsfPollController`, autenticado pela mesma policy `sufficit-ssf-transmitter`.

| Requisito RFC 8936 | Estado |
|---|---|
| Entrega sob demanda | Sim |
| Reconhecimento (`ack`) | Sim, pela fila de entregas |
| `maxEvents` / `returnImmediately` | Parcial |

## Lacunas

- Sem SET cifrado.
- Sem repetição automática com backoff em push; a falha é registrada e o evento
  para um receptor indisponível não é reenviado.

## Testes

`SharedSignalsTests`, `SharedSignalsTests.Streams`, `SsfStreamsControllerTests`,
`SsfSubscriptionMatcherTests`.
