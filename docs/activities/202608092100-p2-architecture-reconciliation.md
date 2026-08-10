# Reconciliação dos refactors arquiteturais P2

> **Status:** COMPLETED em 2026-08-09 como decisão de escopo do
> plano de evolução arquitetural P2.

## `SufficitIdentityOptions`

A inspeção do binding mostrou que a façade já contém somente propriedades
tipadas por feature (`Tokens`, `Dpop`, `Mtls`, `Jar`, `Jarm`, `Ciba`,
`SharedSignals`, `Database`, etc.). Serviços consomem esses objetos específicos
e o contrato JSON é compatível. Mover as declarações para arquivos físicos
separados não altera dependências, ownership, binding, testes ou blast radius;
seria churn sem benefício mensurável. A façade única foi mantida.

As novas decisões deste ciclo reforçam o desenho existente: formato de token é
resolvido por `AccessTokenFormatPolicy`, revogação por `MtlsOptions`, JWKS remoto
por `JarOptions` e orçamento criptográfico por `VaultOptions`, sem adicionar
novas flags soltas ao host.

## `AuthorizationController`

A decomposição por grant continua válida, mas já pertence ao plano canônico
o item P1.7 do plano canônico de autorização, que exige contrato comum de emissão,
centralização de claims/resources/lifetime/sender constraints e migração de um
grant por vez sob caracterização. Fazer apenas o roteamento ou mover métodos de
arquivo neste ciclo criaria uma abstração nominal sem reduzir acoplamento.

O item duplicado foi removido deste plano; o trabalho não foi declarado
implementado nem descartado, e permanece visível no plano canônico com seus
critérios completos. Isso preserva a regra de uma única implementação ativa
para um refactor transversal.
