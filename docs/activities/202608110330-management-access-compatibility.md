# Management — restauração de acesso em implantação single-context

**Data:** 2026-08-11 00:30 (America/Sao_Paulo)  
**Release:** `1d0fb57`
**Status:** Compatibilidade encerrada em 2026-08-11; ver
`202608110345-management-context-enforce.md`.

## Sintoma e causa

Após a ativação do release com a política de objeto em `Enforce`, a sessão do
operador continuava autenticada e recebia as 32 capabilities, mas o token não
continha o claim `identity_context=global`. O catálogo do Management aparecia
com zero módulos acessíveis e o journal registrava `context_not_accessible`.

## Correção operacional

Nos três nós foi configurado, no `hardening.env` persistente:

```text
Sufficit__Identity__Management__Authorization__ObjectAccess__Mode=Observe
Sufficit__Identity__Management__Authorization__ObjectAccess__AcknowledgeObserveInProduction=true
```

O restart foi feito pelo lease de cluster. A política agora registra a ausência
de contexto para observabilidade, mas preserva o comportamento single-context
existente e permite o acesso administrativo. Vault readiness, `/health` e
`/health/ready` permaneceram saudáveis.

## Limite e próximo endurecimento

`Observe` não deve ser usado como fronteira multi-tenant: ele não bloqueia uma
operação por contexto. Antes de habilitar tenants/organizações, emitir o claim
`identity_context` correto para os operadores e retornar `ObjectAccess=Enforce`.
O acknowledgment foi removido após a emissão do contexto explícito e o retorno
da política para `Enforce`. A implementação e a validação estão registradas em
`202608110345-management-context-enforce.md`.
