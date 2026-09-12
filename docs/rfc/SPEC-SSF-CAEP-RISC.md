# Shared Signals Framework, CAEP e RISC

| | |
|---|---|
| Papel | Transmissor (Transmitter) |
| Abrangência | **C — Parcial** |
| Origem | Próprio |
| Specs | OpenID SSF 1.0, CAEP 1.0, RISC 1.0 — todas **Final** desde setembro de 2025 |

O envelope e a entrega estão em
[RFC-8417-SECURITY-EVENT-TOKEN.md](RFC-8417-SECURITY-EVENT-TOKEN.md). Aqui está a
semântica dos sinais.

## Superfície

| Papel | Caminho |
|---|---|
| Configuração do transmissor | `GET /.well-known/ssf-configuration` |
| Gestão de streams | `/ssf/streams` (`SsfStreamsController`) |
| Poll | `SsfPollController` |

A gestão de stream exige a policy `sufficit-ssf-transmitter`: bearer com escopo
dedicado e, por padrão, evidência de MFA
(`src/sts/ServiceCollectionExtensions.cs:890-894`). `SharedSignals:RequireMfa`
desligado é achado reportado pela verificação de postura
(`src/sts/Security/StsProductionPostureContributor.cs:50-52`).

## Eventos emitidos

`src/sts/SharedSignals/CaepEventGenerator.cs:12-20`:

| Evento | URI | Gatilho |
|---|---|---|
| Session Revoked | `…/caep/event-type/session-revoked` | Logout, revogação de sessão, mutação de credencial |
| Credential Change | `…/caep/event-type/credential-change` | Troca de senha, passkey criada ou removida, 2FA alterada |
| Device Change | `…/caep/event-type/device-change` | Registro de passkey (`AspNetCoreIdentityPasskeyService.cs:202`) |
| Assurance Level Change | `…/caep/event-type/assurance-level-change` | Mudança de LoA da sessão |
| RISC Verification | `…/risc/event-type/verification` | Teste de stream, sob demanda |

Os gatilhos são acoplados por `SharedSignalsSecurityEventTrigger`, não espalhados
pelos serviços de conta.

## Assinatura de stream

`SsfSubscriptionMatcher` decide quais streams recebem cada evento por assunto e
tipo (`src/sts/SharedSignals/SsfSubscriptionMatcher.cs`). Um stream criado sem
filtro recebia tudo — o comentário em `SsfStreamsController.cs:135` registra que
essa era a configuração mais ampla possível e foi restringida.

## Proteção do endpoint do receptor

O `endpoint_url` de um stream de push passa por
`SafeHttpHandlerFactory.ValidateRequestUri` (`SsfStreamStore.cs:181`). Sem isso,
quem pudesse criar um stream transformaria o transmissor num scanner de rede
interna — um SSRF com credencial.

## Lacunas

| Item | Estado |
|---|---|
| Papel de **receptor** (consumir sinais de terceiros) | Não implementado |
| Repetição com backoff em push | Não |
| Verificação de stream por `verification_endpoint` conforme SSF §7.1.4 | Parcial |
| `Continuous Access Evaluation` aplicado aos próprios tokens | Não — os sinais são emitidos, não consumidos |

A última linha é a mais relevante: o Identity **avisa** os outros sobre revogação,
mas não **recebe** sinais externos para revogar sessões próprias.

## Comparação de mercado

Keycloak só chegou a transmissor SSF em caráter experimental na 26.7 (2026). Ter
push e poll com CAEP e RISC funcionando coloca este ponto acima da maioria dos
concorrentes open-source.

## Testes

`SharedSignalsTests`, `SharedSignalsTests.Streams`, `SsfStreamsControllerTests`,
`SsfSubscriptionMatcherTests`.
