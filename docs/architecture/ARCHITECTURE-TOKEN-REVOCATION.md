# Revogação de tokens e limpeza de registros

## Responsabilidade e integração

`SufficitOpenIddictTokenStore`, em `src/sts/Tokens`, é um adaptador de
persistência do runtime OAuth/OIDC. Seu registro usa `ReplaceTokenStore` na
composição do módulo STS. `Server` continua como único executável e
composition root; `Core` mantém o modelo compartilhado e o `AppDbContext`.
Não há nova dependência em UI, contrato público, tabela ou migração.

Isso segue [a arquitetura do repositório](ARCHITECTURE-REPOSITORY.md) e mantém
os chamadores usando `IOpenIddictTokenManager`. A correção também se encaixa
na centralização futura de emissão/revogação prevista em
[PLAN-IDENTITY.md, seção B1](../plans/PLAN-IDENTITY.md): não cria outro fluxo de
emissão nem transfere regras de protocolo para controllers.

## Por que especializar o store

A configuração `DisableBulkOperations=true` contorna a incompatibilidade do
MariaDB com o `DELETE` de poda gerado pelo OpenIddict, que contém `LIMIT` em
subconsulta. Porém, a opção também desativa as atualizações em conjunto.
Na revogação por autorização, o fallback carrega a cadeia inteira e executa
`SaveChangesAsync` por token, repetindo a detecção de alterações do EF.

O adaptador especializa somente `RevokeByAuthorizationIdAsync`. O filtro e a
transição de status seguem o
[caminho bulk do OpenIddict 7.7](https://github.com/openiddict/openiddict-core/blob/7.7.0/src/OpenIddict.EntityFrameworkCore/Stores/OpenIddictEntityFrameworkCoreTokenStore.cs):
tokens associados à autorização informada, cujo status ainda não seja
`revoked`, recebem esse status em um único `ExecuteUpdateAsync` parametrizado.
Esse comando não contém paginação nem `LIMIT` em subconsulta.

A chamada executa imediatamente, retorna a quantidade de linhas alteradas,
propaga cancelamento/falhas e participa da transação do contexto, quando
houver. Não materializa tokens, não chama `SaveChangesAsync` e não salva
alterações pendentes de outras entidades. Como o bulk nativo, não sincroniza
automaticamente objetos já rastreados; os chamadores não devem interpretar
esses objetos como uma releitura do banco após a operação.

A opção global não é alternada durante a chamada: isso introduziria uma
corrida com outros requests e com o worker de limpeza. Os demais métodos
continuam herdados do store oficial. Uma atualização futura de OpenIddict ou
do provider deve reavaliar a necessidade desse adaptador e executar os testes
de contrato antes de removê-lo.

## Revogação e limpeza têm tempos diferentes

Revogação invalida credenciais durante a operação de segurança. Ela não deve
ser delegada ao background, inclusive quando acionada pela detecção de replay
de refresh token. As regras de tolerância a retries e validação de tokens
continuam no OpenIddict.

`OpenIddictPruningService` remove fisicamente os registros elegíveis usando
os managers oficiais: tokens primeiro, autorizações depois. Em produção,
o comando `--prune-tokens` é agendado a cada seis horas somente no Castrum;
`RunInWebHost=false` desativa `OpenIddictPruningWorker` em todas as APIs.
O worker opcional mantém a execução na inicialização e a cada seis horas
para instalações sem agendador externo. A retenção padrão é de 30 dias pela
data de criação; um token válido e ainda não expirado não é removido apenas
por ser antigo. A revogação especializada não altera esse comportamento nem
o contorno de compatibilidade SQL da limpeza. Consulte o
[runbook de limpeza e alerta de atraso](../operations/RUNBOOK-TOKEN-PRUNING.md).

## Contrato de validação

- `OpenIddictTokenStoreTests`: cadeia de 2.000 tokens em estados diferentes,
  um único `UPDATE` sem carregar entidades, quantidade alterada, idempotência,
  cancelamento, isolamento de outras autorizações e tokens sem autorização,
  rollback, preservação de alterações pendentes e limpeza posterior.
- O mesmo contrato executa em SQLite e MariaDB real. O teste MariaDB usa
  `SUFFICIT_IDENTITY_MARIADB_CONNECTION`, cria um schema temporário próprio
  e o remove no `finally`. Sem essa variável, a verificação é obrigatória no
  CI e não é executada localmente. Nunca apontar essa variável para produção.
- `RefreshTokenTests`: registro do store pelo módulo e replay fora da
  tolerância com o contorno de bulk ligado; o refresh token rotacionado também
  deve ser rejeitado. O teste envelhece apenas o registro resgatado, sem mudar
  a tolerância do protocolo ou aguardar o relógio.
- `OpenIddictPruningWorkerTests`: retenção, preservação de tokens válidos e
  remoção exclusiva de autorizações ad hoc órfãs elegíveis.

Os testes controlam a quantidade de comandos e a materialização, não um
limiar de milissegundos dependente da máquina. A recuperação de CPU/memória
em produção e a origem das revogações precisam de evidência operacional
separada. A correção não encerra os gates de concorrência entre réplicas,
replicação ou conformance dos planos existentes.
