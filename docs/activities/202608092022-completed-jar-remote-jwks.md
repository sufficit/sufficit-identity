# JAR com `jwks_uri` remoto seguro

> **Status:** COMPLETED em 2026-08-09. Entrega correspondente ao P1.3 de
> `PLAN-CLAUDE-FABLE-5-REMAINING.md`.

## Resultado

- JAR resolve primeiro o JWKS público embutido do cliente e usa `jwks_uri`
  somente quando não existe chave embutida; metadados conflitantes falham
  fechados.
- Management e DCR aceitam e persistem apenas URI HTTPS pública, absoluta, sem
  user-info ou fragmento. IP literal privado, loopback e special-use é negado
  na entrada.
- O fetch usa o transporte de egress seguro: redirect automático desabilitado,
  resolução DNS conectada ao IP validado e bloqueio de redes privadas contra
  SSRF e DNS rebinding.
- Resposta, timeout, quantidade de chaves e cache têm limites configuráveis. O
  parser aceita somente chaves públicas RSA/EC para assinatura, rejeita
  material privado e `kid` duplicado.
- Um `kid` desconhecido força refresh imediato para permitir rotação. Stale em
  falha remota só pode atender um `kid` já conhecido; não há fallback para
  chave diferente ou metadata não registrada. Sem `kid`, conjuntos com mais de
  uma chave são ambíguos e rejeitados.

## Superfícies alteradas

- `PublicHttpsUriPolicy`: política compartilhada por STS e Management.
- `RemoteJwksProvider` e `JarSigningKeyResolver`: fetch, cache e resolução.
- `CreateManagementClientCommand`, `UpdateManagementClientCommand`, API de
  Management e DCR: registro e leitura de `jwks_uri`.
- `JarOptions` e `appsettings.json.template`: limites operacionais explícitos.

## Validação

- Build do projeto de testes: 13 projetos, 0 erros, 0 warnings.
- Testes focados de JAR, Management e DCR: 45 aprovados, 0 warnings.
- Casos cobertos: URI HTTP/privada, redirect, excesso de tamanho, material
  privado, `kid` ausente, rotação, stale-if-error e cache bounded.
- Template de configuração validado com `jq empty`.
