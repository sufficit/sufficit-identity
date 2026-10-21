# Reset do usuário teste@sufficit.com.br para perfil de telefonia Schreiber

Horário: 2026-10-21 10:30 -03. Solicitado pelo dono nesta sessão.

## Alvo

- Usuário `ee277377-f229-4552-b97a-c8f6e73fd36c` (`teste@sufficit.com.br`).
- Cliente: SCHREIBER LOGISTICA LTDA (matriz), contexto
  `026246a8-51a7-4859-91e0-b06e1bebb045` (CNPJ 10349430000177).

## O que foi feito

1. Senha redefinida via `POST api/users/{id}/reset-password` (token temporário
   de operador, auditado).
2. 31 claims `entitlements` removidos via `DELETE api/claims/{id}` (contextos
   global, Sufficit, CLIENTE PARA TESTE 103333 e próprio usuário).
3. Adicionado o conjunto padrão de usuário de telefonia de cliente via
   `POST api/claims`, todos em `key:026246a851a7485991e0b06e1bebb045`:
   `telephonyclient`, `phonecalls`, `audioupdate`, `balanceview`, `payment`,
   `aiuser`. Não há preset no código; o conjunto é o mais frequente na base
   (797 de ~1.100 usuários de contexto único de cliente).
4. Role `manager` (`1295464c-d7d4-458a-a480-1a77919b0228`) removida por SQL
   direto — a Management API não expõe roles:

   ```sql
   DELETE FROM userroles
    WHERE UserId='ee277377-f229-4552-b97a-c8f6e73fd36c'
      AND RoleId='1295464c-d7d4-458a-a480-1a77919b0228';
   UPDATE users SET SecurityStamp=UPPER(REPLACE(UUID(),'-','')),
                    ConcurrencyStamp=UUID()
    WHERE Id='ee277377-f229-4552-b97a-c8f6e73fd36c';
   ```

   A troca do SecurityStamp força revalidação das sessões existentes.

## Mantido

- Claim `name` ("Teste de funcionalidades da Sufficit"): tipo reservado, não
  editável pela API e sem efeito de autorização.

## Observação

`aiuser` pode ser reprovisionado pelo `ScopeEntitlementProvisioner` em
`aiuser:000…0` (contexto próprio) se o usuário aprovar escopo de AI.

## Painel de telefonia (11:10 -03)

Adicionados via `POST api/claims`, no contexto da Schreiber:
`telephony.panel:026246a851a7485991e0b06e1bebb045` e
`telephony.monitor:026246a851a7485991e0b06e1bebb045`.

Os mesmos itens entraram nos presets `telephony` (padrão) e `operator` em
`intranet.entitlementpresetitems`; a validação de chave pontuada foi liberada
em sufficit-standard `bfa660b` (teste em sufficit-endpoints `288e841`).
