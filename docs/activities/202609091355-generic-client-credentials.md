# Credenciais iniciais gerenciadas e fronteira genérica

## Objetivo

Manter no provedor somente capacidades genéricas de autenticação e ciclo de
vida de credenciais. Neutralizar os testes e a documentação da alteração local
inicial, preservando sua cobertura e a melhoria funcional.

## Estado e mudanças

A implementação iniciada em `818ffc8`, sobre `637c35b`, passou a aceitar datas na
primeira credencial de uma aplicação. `ClientCredentialRegistry` usa o registro
gerenciado e promove a aplicação a confidencial dentro da transação existente.
Não persiste cópia do segredo no campo legado. Sem datas, conserva o comportamento
anterior.

`SufficitOpenIddictApplicationManager` reconhece a credencial persistida na
validação da aplicação. Somente o diagnóstico de ausência de segredo/chave
`ID2113` é dispensado nesse caso; outras validações permanecem ativas.
A autenticação continua verificando hash, agendamento, expiração e revogação.
Não houve modificação adicional nesses dois arquivos nesta correção.

Os testes agora são `InitialManagedCredentialTests`: usuários fictícios neutros
e claims opacos `urn:example:`. A identidade humana e a identidade da aplicação
continuam independentes. A cobertura inclui assinatura JWT, validade, rotação,
revogação, credencial incorreta/de outra aplicação, negativa de administração
e preservação de outras regras de validação.

O [guia de credenciais](../usage/USAGE-MANAGED-CLIENT-CREDENTIALS.md) documenta
somente cadastro OAuth, validade, emissão e revogação. Documentação específica
de uma aplicação consumidora foi retirada desta árvore e preservada fora do
repositório. O índice foi atualizado.

## Validação

```bash
dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore \
  -p:SufficitUseLocalSui=false -p:TreatWarningsAsErrors=true \
  --filter FullyQualifiedName~InitialManagedCredentialTests
```

Executado via `rtk dotnet test`: **7 aprovados, zero falhas e zero warnings**,
3,0 segundos. `git diff --check` passou. Verificação de referências confirmou
que os nomes antigos de arquivo/classe não permanecem em documentação ou fontes.

A implementação funcional anterior já havia passado pela suíte completa de
1092 testes. Nesta correção foram reexecutados os sete testes afetados; o código
funcional permaneceu igual.

## Limites e entrega

Alteração e commit locais, sem implantação, push ou merge. Nenhuma conta ou
credencial produtiva foi criada. A expiração de um segredo bloqueia novas
emissões; não revoga, por si só, tokens já emitidos.

A interpretação de claims e a autorização dos recursos de cada aplicação
consumidora continuam fora do provedor. Nenhum domínio comercial foi acrescentado
ao modelo de identidade.
