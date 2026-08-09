# Avaliação Claude Fable 5 — plano de implementação remanescente

> **Status:** ACTIVE. Reconciliado em 2026-08-09 contra
> `6b90e70`. Origem: avaliação interna `EVALUATION-2026-08-09-claude-fable-5.md`
> (mantida fora do versionamento após a reconciliação).
>
> Este documento contém somente trabalho ainda aplicável. Ele não incorpora a
> nota de mercado nem transforma observações informativas em bloqueadores. Onde
> já existe um plano canônico, este plano registra a dependência e o critério de
> fechamento, sem criar uma segunda implementação concorrente.
>
> Contributors modulares, acknowledgements estruturados, fail-closed efetivo,
> defaults seguros e invariantes PKCE/JAR foram entregues e removidos deste
> plano; evidências em
> [`202608091904-completed-production-posture-contributors.md`](../activities/202608091904-completed-production-posture-contributors.md)
> e
> [`202608091911-completed-secure-policy-defaults.md`](../activities/202608091911-completed-secure-policy-defaults.md)
> e
> [`202608091918-completed-pkce-jar-invariants.md`](../activities/202608091918-completed-pkce-jar-invariants.md).

## Resultado da reconciliação

O diagnóstico central do relatório é válido: a maior lacuna atual não está na
correção criptográfica dos protocolos, mas na diferença entre controles
implementados e controles efetivamente aplicados em produção. O primeiro
objetivo é fazer o processo recusar uma postura permissiva não reconhecida; o
segundo é fechar os poucos desvios de protocolo e custódia de chaves que ainda
permitem downgrade ou confiança excessiva.

Quatro recomendações precisam de ajuste antes de serem implementadas:

1. `Observe` não será removido abruptamente de SCIM e token exchange. O STS já
   atende tráfego de produção, portanto o modo permanece durante uma janela de
   inventário, passa a exigir reconhecimento explícito e expira depois da
   migração para `Enforce`.
2. Os vários enums de enforcement não serão unificados antes dos controles.
   Primeiro será criado um contrato comum de contribuição para a postura; a
   consolidação dos tipos só ocorrerá se ainda reduzir complexidade depois do
   rollout.
3. DPoP e mTLS não terão seus membros de `cnf` apenas mesclados. Hoje o validador
   DPoP desativa a validação PoP nativa do OpenIddict; mesclar sem alterar a
   validação faria uma das duas provas deixar de ser exigida. A primeira entrega
   deve rejeitar a combinação e garantir exatamente um sender constraint.
4. O vault não será ligado sem migração dos valores `pt1`. O estado final é
   `PassThroughKeyVault` restrito a Development, alcançado por rollout e não por
   uma quebra imediata de inicialização.

## Restrições de entrega

- Preservar grants, clientes, usuários, rotas e integrações durante o rollout.
- Introduzir observabilidade e inventário antes de trocar uma decisão de
  compatibilidade por negação.
- Manter mudanças de schema aditivas e compatíveis com rolling deployment.
- Não registrar tokens, proofs, códigos, valores de segredo, chaves ou conteúdo
  de request objects.
- Toda exceção temporária de produção deve ter identificador estável,
  justificativa, responsável e expiração; um booleano genérico e permanente não
  é critério suficiente.
- Itens operacionais continuam nos runbooks e planos canônicos; este plano só os
  referencia como gate de release.

## Decisão por achado

| Achado | Decisão | Evidência atual e destino |
| --- | --- | --- |
| S3 — SCIM Observe permite cliente fora da allow-list | **Aceito com rollout, P0** | O default já é `Enforce`, mas `ScimClientHandler` concede em `Observe`. Tornar o uso temporário, reconhecido e bloqueado pelo posture check; remover após a janela de migração. |
| S4 — proveniência de token exchange em Observe | **Aceito com rollout, P0** | `TokenExchangeOptions.ProvenanceMode` agora inicia em `Enforce`; P0.2 mantém somente o inventário e a remoção de overrides `Observe` existentes nos ambientes. |
| S5 — vault plaintext por default | **Aceito, gate de produção P0** | `Enabled=false` e `RequireEncryptionInProduction=false` ainda selecionam `pt1` fora de Development. A migração canônica permanece no plano GLM/Vault. |
| S6 — KEK no mesmo domínio do banco | **Aceito, P1** | O backend disponível é Data Protection, persistido no mesmo `AppDbContext` e protegido pelo certificado de assinatura. Separar certificado/KEK e entregar KMS/HSM em P1.1. |
| S7 — signing keys nunca aposentadas | **Aceito, P1** | Rotação cria nova versão; nenhum fluxo define `RetiredAtUtc`. Implementar lifecycle completo em P1.1. |
| S9 — vault secrets sem escopo por item | **Aceito, P1** | O serviço envia o nome no `ManagementResource`, mas `VaultSecrets` não pertence a `ItemResourceTypes` e não existe política de namespace. Fechar junto do modelo de contexto/tenant. |
| S12 — mTLS sobrescreve DPoP em `cnf` | **Aceito com remediação ajustada, P0** | Os handlers escrevem a mesma claim nas ordens `+500` e `+600`. Rejeitar combinação até existir validação cumulativa comprovada. |
| S13 — comparação AAD | **Aceito, correção curta P0** | Trocar `SequenceEqual` por `CryptographicOperations.FixedTimeEquals` e testar tamanhos diferentes. |
| S13 — fallback plaintext do resolver | **Aceito, P0** | `VaultBackedClientSecretResolver` retorna texto cru em qualquer `FormatException`, inclusive com vault real. Permitir fallback apenas no backend de compatibilidade. |
| S13 — `jwks_uri` de JAR | **Aceito como gap funcional, P1** | O código e o comentário prometem fallback, mas `ResolveSigningKeysAsync` lê apenas JWKS embutido. Implementar fetch seguro ou rejeitar o metadado de forma explícita até a implementação. |
| S13 — revogação mTLS | **Aceito como defesa em profundidade, P1** | Thumbprint por cliente limita o impacto, mas `NoCheck` é fixo. Tornar a política configurável e documentar o comportamento de proxy. |
| S13 — replay DPoP distribuído | **Sem mudança funcional** | O get/set isolado não é a autoridade final: `RollingDpopReplayCache` inclui insert único no banco. Adicionar somente teste de composição para impedir remoção acidental dessa camada. |
| S13 — orçamento de nonce GCM | **Diferido, P2** | Risco teórico dependente de volume. Medir operações por versão e definir limite antes de criar rotação por contagem. |
| S13 — CSP | **Já canônico** | Calibração e enforcement permanecem em `PLAN-PRODUCTION-READINESS.md` e `RUNBOOK-CSP-CALIBRATION.md`. |
| S13 — `EnvelopeCrypto.Wrap/Unwrap` | **Aceito como limpeza, P2** | Corrigir comentários/modelo que atribuem o wrapping real a AES-GCM ou remover o caminho morto e seu teste. |

Referência normativa de S11: [RFC 9101, seções 4 e
5](https://www.rfc-editor.org/rfc/rfc9101.html#section-4).

## P0 — bloquear postura insegura e downgrades imediatos

### P0.2 Concluir os rollouts que hoje permanecem observacionais

**Alvos:** SCIM, token exchange, personal tokens, CIBA, credential mutations,
public origin e autorização Management.

- [ ] SCIM: inventariar clientes negados nos ambientes, provisionar a
  allow-list e remover overrides `Observe` depois de uma release sem decisões
  de compatibilidade
- [ ] Token exchange: caracterizar `azp`/`client_id` dos subject tokens,
  corrigir emissores ambíguos, remover overrides de provenance `Observe` e
  manter atenuação de scopes/resources como invariante
- [ ] Personal tokens e CIBA: concluir inventários e remover overrides
  `Observe` conforme `PLAN-SECURITY-HARDENING-WAVE-2.md`
- [ ] Credential mutations: provar a cerimônia real de step-up e remover
  overrides `Audit`, conforme `PLAN-GPT-5-REMAINING.md`
- [ ] Public origin: configurar issuer/public URL canônico em todos os hosts e
  remover overrides `Audit`; nenhum link de segurança pode depender de Host não
  confiável
- [ ] Management: auditar as configurações implantadas e remover
  `RequireAuthorization=false` fora de Development, salvo acknowledgement
  temporário que bloqueie certificação/go-live

**Concluído quando:** produção não contém um modo permissivo sem acknowledgement
válido e todas as exceções temporárias têm data de remoção observável.

### P0.4 Impedir downgrade de sender constraint

**Alvos:** handlers DPoP/mTLS, FAPI policy e testes de token/userinfo.

- [ ] Detectar a presença simultânea de DPoP e certificado mTLS válido antes da
  emissão e rejeitar a requisição com erro de protocolo estável
- [ ] Garantir por teste que exatamente um de `cnf.jkt` ou `cnf.x5t#S256` é
  emitido e que o tipo de token acompanha o mecanismo escolhido
- [ ] Cobrir authorization code, client credentials, refresh e token exchange,
  inclusive tentativas de trocar o mecanismo no refresh
- [ ] Só considerar suporte cumulativo futuro depois que resource server e STS
  provarem as duas validações; não apenas depois de mesclar o JSON de `cnf`

**Concluído quando:** apresentar dois mecanismos nunca reduz o vínculo para um
mecanismo diferente do selecionado pela política.

### P0.5 Fechar plaintext e fallbacks criptográficos em produção

**Alvos:** `VaultOptions`, registro DI do vault, client-secret resolver e crypto.

- [ ] Executar a migração de `pt1`, configuração e credenciais descrita em
  `PLAN-GLM-5-2-REMAINING.md` P0.1 e no runbook do vault
- [ ] Alterar o estado final para `RequireEncryptionInProduction=true` por
  default e impedir `PassThroughKeyVault` fora de Development
- [ ] Fazer o resolver de client secrets aceitar referência plaintext apenas
  quando o backend indicar explicitamente modo de compatibilidade; com vault
  real, formato inválido deve falhar fechado
- [ ] Trocar a comparação do hash AAD por
  `CryptographicOperations.FixedTimeEquals` sem remover a autenticação GCM
- [ ] Adicionar testes de startup não-Development, migração `pt1`, ciphertext
  inválido, AAD incorreto e ausência de fallback plaintext com vault habilitado

**Concluído quando:** nenhum consumidor de `IKeyVault` consegue persistir ou
resolver segredo reversível em produção e valores legados têm migração e
rollback documentados.

## P1 — custódia de chaves, lifecycle e autorização granular

### P1.1 Separar a KEK e implementar lifecycle real de signing keys

**Plano canônico relacionado:** `PLAN-SECURITY-HARDENING-WAVE-2.md` P2.5 e
`PLAN-VAULT.md`.

- [ ] Adicionar backend de certificado dedicado e backend KMS/HSM para
  `IVaultKeyEncryptionKeySource`; o certificado de proteção DP não pode ser o
  certificado de assinatura de tokens
- [ ] Falhar startup quando vault estiver ativo e a key ring/KEK não satisfizer
  a política do ambiente
- [ ] Modelar signing key como `active`, `retiring`, `retired` ou `revoked`, com
  uma única chave de emissão ativa e transições auditadas
- [ ] Ao rotacionar, parar de emitir com a versão anterior, mantê-la em JWKS
  pelo maior lifetime verificável e definir `RetiredAtUtc` ao fim do overlap
- [ ] Implementar revogação emergencial que remova o `kid` de JWKS e impeça
  `SignAsync`/`VerifyAsync`, com impacto explícito sobre tokens ainda válidos
- [ ] Proteger rotação com lock distribuído, idempotência, journal e testes de
  concorrência, restauração, perda de KEK e rollback

**Concluído quando:** dump do banco não basta para recuperar a KEK, uma chave
antiga deixa de ser confiável em prazo definido e comprometimento tem caminho
de revogação exercitado.

### P1.2 Autorizar named secrets por namespace

**Plano canônico relacionado:** `PLAN-GLM-5-2-REMAINING.md` P0.3.

- [ ] Definir namespaces, ownership/context e regra de herança para nomes de
  segredo antes de expor novos capabilities
- [ ] Adicionar `VaultSecrets` ao conjunto de recursos por item e exigir ID
  normalizado para get/put/delete
- [ ] Filtrar listagem pelo mesmo contexto; capability global não pode revelar
  nomes de outro namespace
- [ ] Manter break-glass separado, auditado e não atribuível por APIs comuns
- [ ] Testar listagem, nome adivinhado, overwrite/delete cross-context e
  normalização ambígua

**Concluído quando:** `identity.vault.secrets.manage` autoriza uma operação, mas
o namespace/context decide sobre qual segredo ela pode ocorrer.

### P1.3 Completar chaves remotas de JAR com egress seguro

- [ ] Até existir fetch seguro, corrigir mensagens/docs e rejeitar explicitamente
  clientes JAR que tenham somente `jwks_uri`; não anunciar suporte inexistente
- [ ] Implementar resolução HTTPS por `SafeOutboundHttp`, sem redirects, com
  validação DNS/IP, limite de tamanho, timeout, cache bounded e falha fechada
- [ ] Definir política de refresh/rotação por `kid`, cache stale e indisponibilidade
  remota sem aceitar chave fora do metadata registrado
- [ ] Cobrir SSRF, DNS rebinding, resposta excessiva/malformada, key rotation,
  `kid` ausente e indisponibilidade

**Concluído quando:** `jwks_uri` funciona conforme anunciado sem criar uma nova
rota de SSRF nem fallback para chave não confiável.

### P1.4 Tornar revogação mTLS e topologia de proxy verificáveis

- [ ] Adicionar política configurável `NoCheck`, `Online` ou `Offline`, com
  timeout/failure mode explícitos e default documentado por tipo de pinning
- [ ] Validar em startup como o certificado chega ao app; header encaminhado só
  é aceito de proxy confiável e deve ser removido de conexões não confiáveis
- [ ] Documentar overlap e revogação por cliente e adicionar testes com cadeia
  expirada, revogada, indisponibilidade de CRL/OCSP e header forjado

**Concluído quando:** a confiança não depende implicitamente da topologia e o
operador escolhe conscientemente a política de revogação.

## P2 — manutenção e evolução arquitetural

### P2.1 Reduzir blast radius sem misturar a mudança com os gates P0

- [ ] Decompor `AuthorizationController` por grant conforme
  `PLAN-GLM-5-2-REMAINING.md` P1.7, preservando rotas e caracterização de tokens
- [ ] Dividir `SufficitIdentityOptions` por feature e manter uma façade de
  binding compatível por uma release
- [ ] Reavaliar a unificação dos enums de enforcement depois que contributors e
  acknowledgements estiverem estáveis; não criar uma migração de tipos sem
  benefício mensurável
- [ ] Remover ou corrigir `EnvelopeCrypto.Wrap/Unwrap` e os comentários de
  entidade que não descrevem o wrapping real por Data Protection

### P2.2 Evoluir formato de token e limites criptográficos com evidência

- [ ] Selecionar JWT/reference token por cliente/recurso conforme
  `PLAN-GPT-5-REMAINING.md` P1.13, com migração sem flag day
- [ ] Medir encryptions por key name/version e definir orçamento de mensagens
  antes de automatizar rotação por contagem de nonce GCM
- [ ] Manter teste de composição garantindo que `RollingDpopReplayCache`
  contenha a camada atômica de banco enquanto o cache distribuído usar get/set

### P2.3 Prova externa de produção

- [ ] Executar conformance OAuth/OIDC/FAPI/SSF aplicável às capabilities
  anunciadas
- [ ] Commissionar auditoria externa de DPoP, JAR/JARM, CIBA, mTLS, token
  exchange e vault após P0/P1
- [ ] Concluir CSP, Redis multi-replica, certificados e disaster recovery em
  `PLAN-PRODUCTION-READINESS.md`

## Sequência de rollout

1. **Release de observação:** contributors completos, telemetry, testes e
   acknowledgements estruturados; sem mudança de decisão para tráfego existente.
2. **Inventário e correção:** remover findings reais, migrar `pt1`, corrigir
   clientes/subject tokens e registrar somente exceções temporárias.
3. **Release fail-closed:** remover o guard de presença, ligar o default real,
   fechar PKCE/JAR/sender constraint/fallbacks e bloquear novas regressões.
4. **Expiração de compatibilidade:** retirar acknowledgements vencidos,
   `Observe` de SCIM após uma release limpa e adapters de configuração antigos.
5. **Custódia e certificação:** concluir KMS/HSM, lifecycle de signing keys,
   namespaces e provas externas antes do go-live irrestrito.

## Verificação mínima

- `dotnet build Sufficit.Identity.sln -c Release`
- `dotnet test src/tests/Sufficit.Identity.Tests.csproj -c Release`
- Testes focados de posture check e startup não-Development
- Testes de Management/Provisioning/DCR para PKCE
- Testes JAR de parâmetros externos, tipos estruturados, replay e `jwks_uri`
- Testes DPoP/mTLS de emissão, refresh e consumo
- Testes vault com MariaDB para rotação, retirement, concorrência e migração
- Rehearsal de rolling deployment antes de remover cada compatibilidade

## Gate de encerramento

Este plano pode ser arquivado somente quando:

- todo modo permissivo de produção está enforcing ou possui exceção temporária
  ainda válida e auditável;
- Management, provisioning e DCR compartilham PKCE para todo auth-code client;
- JAR não usa parâmetros externos ao JWT validado;
- DPoP e mTLS não sofrem downgrade quando apresentados em conjunto;
- produção não usa `pt1`/PassThrough e a KEK está fora do domínio do banco;
- signing keys têm overlap, retirement e emergency revoke exercitados;
- os gates canônicos de produção, vault, autorização e auditoria externa foram
  concluídos.
