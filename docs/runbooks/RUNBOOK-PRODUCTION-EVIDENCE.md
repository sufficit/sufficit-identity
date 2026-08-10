# Runbook — evidências de prontidão de produção

## Objetivo

Este runbook fecha a diferença entre um controle implementado no repositório e
um controle comprovadamente ativo em cada ambiente. Ele é o procedimento
canônico dos gates operacionais de
[`PLAN-PRODUCTION-READINESS.md`](../plans/PLAN-PRODUCTION-READINESS.md).

O repositório não contém inventário nem configuração dos ambientes reais.
Portanto, um item deste runbook só pode ser encerrado com evidência produzida
no ambiente e vinculada ao gate da release. Nunca anexe tokens, proofs,
request objects, códigos, ciphertext, segredos, chaves privadas, senhas ou
valores de variáveis de ambiente.

## Registro obrigatório por ambiente

Abra um registro para cada ambiente e release com:

| Campo | Conteúdo mínimo |
| --- | --- |
| Ambiente e release | identificador estável, versão/commit e data UTC |
| Responsáveis | owner técnico e aprovador de segurança/operações |
| Topologia | número de réplicas e identificadores dos serviços externos, sem credenciais |
| Evidências | links imutáveis para configuração redigida, métricas, testes e restore |
| Exceções | finding ID, owner, motivo e expiração UTC |
| Decisão | aprovado, bloqueado ou rollback, com data e aprovador |

Uma exceção temporária usa
`Sufficit:Identity:Security:Acknowledgements:<finding-id>` com `Owner`, `Reason`
e `ExpiresAtUtc`. Não reative um modo permissivo sem esse registro. Remova a
exceção assim que o finding deixar de existir; acknowledgements órfãos também
impedem o startup.

## 1. Postura e remoção de modos permissivos

Capture somente os nomes e valores não secretos abaixo e compare com a
configuração efetiva de **todas** as réplicas:

| Superfície | Estado exigido fora de Development |
| --- | --- |
| SCIM habilitado | `RequireAllowedClient=true`, `ClientPolicyMode=Enforce` e `AllowedClientIds` contendo somente clientes dedicados inventariados |
| Token exchange habilitado | `ProvenanceMode=Enforce`; emissores produzem `azp`/`client_id` não ambíguo e os clientes autorizados continuam explicitamente limitados |
| Personal tokens | `Mode=Enforce`; clientes, escopos, idade de autenticação e lifetime inventariados |
| CIBA habilitado | `ClientPolicyMode=Enforce`; clientes confidenciais possuem grant e allow-list explícitos |
| Credential mutations | `StepUpMode=Enforce`; a cerimônia real de reautenticação foi exercitada |
| Origem pública | `Issuer` ou `PublicUrl` HTTPS canônico configurado e `PublicOrigin:Mode=Enforce` |
| Management habilitado | `RequireAuthorization=true`; `ObjectAccess:Mode=Enforce` e `ProtectedPrincipals:Mode=Enforce` |
| Posture check | `AllowLegacyBooleanAcknowledgements=false`; nenhuma exceção vencida ou sem owner/motivo |

Procedimento:

1. execute uma release de observação e agregue por `ReasonCode` as decisões que
   seriam negadas, sem sujeito, token ou payload;
2. provisione allow-lists, grants, contextos e tiers que forem legítimos;
3. exija uma janela completa de release sem negações de compatibilidade não
   explicadas;
4. altere um grupo de política por vez para `Enforce`, iniciando por canário;
5. exerça casos permitido e negado e confirme o mesmo resultado em cada
   réplica;
6. remova o acknowledgement correspondente e confirme novo startup do canário.

O rollback permitido é a versão anterior ou um acknowledgement limitado ao
finding estável. `RequireAuthorization=false`, `Observe` ou `Audit` sem
acknowledgement válido não são rollback aceito.

## 2. Eliminação de valores `pt1.`

Antes da migração, prove que banco, key-ring compartilhado e autoridades KEK
possuem backup restaurável. Habilite `Sufficit:Vault:Enabled=true` primeiro em
uma réplica de canário e depois em todas as réplicas. O guard de produção não
depende de `RequireEncryptionInProduction`; essa propriedade permanece apenas
por compatibilidade.

Conte somente os marcadores legados persistidos, sem selecionar seus valores:

```sql
SELECT 'vaultsecrets.ciphertext' AS source, COUNT(*) AS legacy_count
FROM vaultsecrets WHERE ciphertext LIKE 'pt1.%'
UNION ALL
SELECT 'vaultpersonalsecrets.ciphertext', COUNT(*)
FROM vaultpersonalsecrets WHERE ciphertext LIKE 'pt1.%'
UNION ALL
SELECT 'identitymetricsconfiguration.secretciphertext', COUNT(*)
FROM identitymetricsconfiguration WHERE secretciphertext LIKE 'pt1.%'
UNION ALL
SELECT 'ssfstreams.authorization', COUNT(*)
FROM ssfstreams WHERE authorization LIKE 'pt1.%';
```

Regrave cada registro pela API/serviço proprietário com o vault real ativo; não
faça transformação textual direta no banco. Registros DPoP e CIBA do cache
distribuído são efêmeros: aguarde o maior TTL configurado após a última réplica
legada sair e prove ausência de leituras `pt1.` por métrica/log agregado, sem
inspecionar ou anexar o valor do cache.

O gate exige simultaneamente:

- `legacy_count=0` para todas as linhas da consulta;
- zero leitura `pt1.` durante uma janela completa definida pela operação;
- novas gravações no formato versionado `v1`, verificadas apenas por contagem;
- restore ensaiado para banco, key-ring/KEK e versão anterior da aplicação;
- owner, janela de rollback e evidência redigida anexados à release.

Consulte também [`RUNBOOK-VAULT.md`](RUNBOOK-VAULT.md) para ativação, rotação e
recuperação.

## 3. Cache compartilhado e múltiplas réplicas

Antes de escalar horizontalmente, registre um `IDistributedCache` Redis real e
mantenha `DistributedCache:RequireShared=true` para os protocolos que dependem
de replay/nonce compartilhado.

1. suba pelo menos duas réplicas apontando para o mesmo cache;
2. produza estado em uma réplica e consuma na outra;
3. tente consumo/replay concorrente e confirme uma única decisão vencedora;
4. reinicie uma réplica e confirme que o estado e TTL continuam autoritativos;
5. simule indisponibilidade do cache e confirme o comportamento fail-closed;
6. anexe apenas contagens, latência, resultado e identificadores redigidos.

## 4. CSP, certificados e disaster recovery

- Execute [`RUNBOOK-CSP-CALIBRATION.md`](RUNBOOK-CSP-CALIBRATION.md) em todos
  os fluxos públicos e Management, remova violações explicadas e configure
  `Csp:ReportOnly=false`.
- Registre thumbprint SHA-256, finalidade, emissor, validade e versão dos
  certificados de assinatura, criptografia, mTLS e KEK. Nunca registre a chave
  ou senha.
- Prove rotação com sobreposição: a chave nova emite, a antiga valida somente
  durante a janela e depois é retirada do conjunto público.
- Prove que a autoridade KEK é distinta da autoridade de assinatura e que
  leitura do banco isoladamente não permite desembrulhar DEKs.
- Restaure banco, cache quando aplicável, key-ring/KEK e certificados em um
  ambiente isolado; valide login, emissão, introspecção, revogação e decrypt de
  uma amostra sintética.

## 5. Conformance e auditoria independente

Execute os perfis OAuth/OIDC/FAPI/SSF correspondentes somente às capabilities
anunciadas pela implantação e guarde versão da suíte, configuração redigida,
resultado e waiver aprovado. Falha normativa bloqueia certificação.

Depois dos cutovers anteriores, forneça à auditoria externa o escopo de DPoP,
JAR/JARM, CIBA, mTLS, token exchange, SSF e vault. Cada finding deve ter
severidade, owner, prazo, correção/reteste ou aceitação formal de risco. O gate
só fecha quando os findings impeditivos forem retestados.

## Critério final

O ambiente está pronto apenas quando todos os registros obrigatórios têm links
válidos, os testes de canário e rollback passaram, não há exceção vencida e o
plano de produção correspondente foi atualizado. Ausência de evidência é item
pendente, não sucesso presumido.
