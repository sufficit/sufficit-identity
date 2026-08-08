# Plano — estado operacional de aplicações OAuth/OIDC

**Status:** pendente
**Criado:** 2026-08-08
**Origem:** lista de aplicações e revisão mobile do Management

## Problema confirmado

`OpenIddictEntityFrameworkCoreApplication` não possui um campo de habilitação
ou desabilitação. A lista atual pode informar apenas `active` porque esse é o
estado efetivamente garantido pelo runtime. Exibir `blocked`, `disabled` ou
`revoked` sem que os endpoints consultem e apliquem a decisão criaria uma
indicação falsa para o operador.

## Decisão recomendada

Criar uma tabela de estado operacional própria, relacionada pelo `ApplicationId`
do OpenIddict, em vez de sobrecarregar `applications.properties`:

- `application_id` (chave única e FK lógica para `applications.id`);
- `status` (`active` ou `disabled` nesta primeira versão);
- `reason` opcional, sem segredos;
- `changed_at_utc`, `changed_by_subject` e `version` para auditoria e
  concorrência otimista.

Ausência de uma linha significa `active`, preservando a compatibilidade com os
clientes já existentes. `revoked` não deve ser um estado da aplicação: tokens,
autorizações e sessões têm ciclo de vida próprio e continuam sendo revogados
pelos serviços OpenIddict existentes.

## Enforcement obrigatório

Antes de adicionar qualquer filtro novo na UI ou na API, a mesma decisão deve
ser aplicada nos pontos abaixo:

1. `connect/authorize` e consentimento;
2. `connect/token`, incluindo refresh token e client credentials;
3. PAR e device authorization/token;
4. introspection, userinfo e qualquer endpoint que aceite `client_id` para
   iniciar uma operação de protocolo;
5. criação/edição/remoção pela Management API, com auditoria e capability
   própria.

O verificador deve devolver um erro OAuth consistente (`invalid_client` ou
`unauthorized_client`, conforme o ponto do protocolo), registrar o client ID e
o estado sem expor dados sensíveis e manter cache/invalidação coerentes com o
cache de aplicações do OpenIddict.

## Rollout seguro

- Criar migração aditiva e índice por `application_id,status`.
- Fazer backfill opcional somente para estados explicitamente conhecidos; a
  ausência continua equivalente a `active`.
- Começar com leitura/telemetria, sem bloquear tráfego.
- Habilitar bloqueio por capability/configuração após testes de authorize,
  token, PAR e device em clientes representativos.
- Permitir alteração manual apenas para clientes não gerenciados por manifesto;
  o manifesto deve ser a fonte de verdade dos clientes declarativos.
- Adicionar auditoria, concorrência otimista e rollback documentado.

## UI depois do enforcement

Expor na lista somente `Todos`, `Ativos` e `Desabilitados`, com descrição da
origem, motivo e data da última alteração. A tela deve mostrar o impacto antes
da confirmação e manter o filtro na URL. Não incluir “revogado” no filtro de
aplicação.

## Critérios de conclusão

- Migração aplicada sem alterar clientes existentes.
- Autorizações, tokens, PAR e device recusam consistentemente uma aplicação
  desabilitada.
- Reativação restaura o fluxo sem apagar tokens ou autorizações históricos.
- API, UI, auditoria e métricas apresentam o mesmo estado.
- Testes de contrato, integração, concorrência, cache e rollback aprovados.
