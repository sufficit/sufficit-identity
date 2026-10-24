# Ensaio entre as três réplicas de produção (D5, 24/10/2026)

Cliente temporário `rehearsal-replicas` (só `client_credentials`), criado pela
API de gestão com um operator token de 1 hora emitido pelo titular
(`clients.read/create/delete`), e apagado no fim (`DELETE` 204, depois 404). O
segredo foi gerado localmente e nunca impresso.

Cada nó foi chamado diretamente em `https://<nó>-apps.sufficit.com.br:26501`,
sem o balanceador.

## Resultados

- **Reuso de prova DPoP entre réplicas:** para cada nó de origem, uma prova
  aceita (200, token DPoP) e outra prova com o **mesmo `jti`** mandada aos
  outros dois nós: recusada nos dois (`invalid_dpop_proof`), nos três pares.
  Controle com `jti` novo no mesmo nó: 200. O registro de `jti` é de fato
  compartilhado (cache + tabela com chave única).
- **Consumo entre réplicas:** um token emitido no eveo chega autenticado ao
  apoint e ao castrum (`403` numa API de gestão = token válido, sem o escopo;
  `401` seria token inválido).
- **Revogação entre réplicas:** não ensaiada. O cliente não tem permissão no
  endpoint de revogação (`unauthorized_client`) e o contrato de criação da
  gestão não expõe permissões de endpoint. Ficou no plano.

## Observação: `htu` do DPoP por nó

Acessados direto, apoint e castrum validam o `htu` contra o host do próprio
nó (o nginx deles repassa o `Host` recebido), enquanto o eveo valida contra a
origem pública. Pelo balanceador todos recebem `identity.sufficit.com.br`,
então para os clientes reais o `htu` é o mesmo nos três. Sem risco: cada nó
aceita uma única URL.
