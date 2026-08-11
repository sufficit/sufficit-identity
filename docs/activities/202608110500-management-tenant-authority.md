# Management — autoridade explícita de tenant

**Data:** 2026-08-11 05:00 (America/Sao_Paulo)
**Status:** Implementado; requer configuração de produção antes do deploy

## Risco eliminado

O adaptador Sufficit concedia todas as capabilities à role `administrator`.
Uma classificação incorreta de role podia, portanto, virar acesso
administrativo ao tenant global.

## Decisão

- A nomenclatura pública passa a ser **tenant**.
- O claim canônico é `identity:tenant`, usando `:` como separador.
- Roles, scopes, capabilities e claims recebidos não comprovam associação a
  tenant.
- A autoridade padrão é o mapa protegido `subject -> tenants`, configurado em
  `Management:Authorization:TenantAccess:SubjectTenants`.
- Claims `identity:tenant` recebidos são removidos e recriados exclusivamente
  com o resultado dessa autoridade.
- O break-glass do Vault não ultrapassa a fronteira de tenant; ele permanece
  limitado à autorização de namespace, sempre com MFA e auditoria.
- A role Sufficit `administrator` só recebe o conjunto completo de capabilities
  quando o mesmo subject possui ao menos um tenant confiável.
- Ausência ou configuração inválida da autoridade é finding de produção sem
  acknowledgment de compatibilidade.

## Configuração

O arquivo `/etc/sufficit/identity/hardening.env` é `root:www-data` e `0640`; o
processo pode lê-lo, mas não alterá-lo. Para o deployment single-tenant atual,
cada operador autorizado precisa de uma atribuição explícita:

```text
Sufficit__Identity__Management__Authorization__ObjectAccess__Mode=Enforce
Sufficit__Identity__Management__Authorization__TenantAccess__ProviderTenantId=global
Sufficit__Identity__Management__Authorization__TenantAccess__SubjectTenants__<sub>__0=global
```

`ProviderTenantId=global` classifica recursos globais do provedor; não concede
acesso. Sem a última linha, o operador não recebe tenant nem acesso ao
Management.

## Cobertura de regressão

- administrador sem atribuição confiável não se torna operador;
- role, scope e capability não produzem tenant;
- claim fornecido pelo chamador é descartado;
- o subject é comparado de forma exata e case-sensitive;
- tenant divergente recebe `tenant_not_accessible`;
- `identity:tenant` permanece reservado na API genérica de claims;
- o posture check bloqueia Management habilitado sem autoridade configurada.
