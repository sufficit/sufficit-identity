# Revogação entre as três réplicas (D5, 28/10/2026)

Fecha o que o [ensaio de 24/10](202610241900-replica-rehearsal.md) deixou em
aberto: revogar num nó e consumir nos outros.

## Método

Cliente temporário `rehearsal-revocation`, criado direto no banco porque o
contrato de criação da gestão não expõe permissões de endpoint: cópia das
permissões de um cliente confidencial existente mais `ept:revocation` e
`ept:introspection`, sem vínculo a usuário de sistema, com credencial extra de
2 horas. O segredo nunca foi impresso. Cada nó foi chamado direto em
`https://<nó>-apps.sufficit.com.br:26501`, sem o balanceador.

Para cada par (nó que emite, nó que revoga), seis pares ao todo: emitir um
token `client_credentials`, sondar os três nós numa API de gestão (`403` =
token válido sem a capability; `401` = token inválido), revogar no outro nó
(`/connect/revocation`, `token_type_hint=access_token`) e sondar de novo,
além de introspecção nos três.

## Resultado

Nos seis pares: antes da revogação `403` nos três nós; revogação `200`; logo
depois `401` nos três e introspecção `active: false` nos três. A revogação é
vista imediatamente por todas as réplicas, sem espera de cache.

## Limpeza

Tokens (12), credencial e cliente apagados. Pedido de token com o cliente em
cada nó, depois da remoção: `401 invalid_client` nos três.
