# Um componente de estado para a console (E5, 24/10/2026)

`ManagementDataView<T>` (`src/ui/Sufficit.Identity.UI.Management/Components/`)
recebe um `ManagementDataResult<T>`, o estado de carga e a ação de tentar de
novo, e mostra carregando, sucesso ou o estado de falha. Fica no
`UI.Management`, não no `UI.Components` que o plano citava: o tipo de resultado
mora no `UI.Management`, e o contrário inverteria a dependência.

## Estados

| Resultado | Apresentação | Ação |
|---|---|---|
| Forbidden | cadeado, aviso | nenhuma |
| StepUpRequired | escudo, aviso | sair e entrar de novo com MFA (o formulário da Home) |
| Unavailable | alerta, perigo | tentar de novo |
| NotFound | busca, neutro | nenhuma |
| Invalid / Conflict | alerta, perigo, mensagem do serviço | tentar de novo |

Região com `aria-live="polite"`, `aria-busy` e `data-outcome`. Lista vazia
continua dentro do sucesso da página (com `SUIEmptyState`), distinta de falha.
Títulos e descrições específicos de cada página ficaram como sobrescrita.

## Migração

- Primeiro as que não tratavam nem Forbidden nem Unavailable: Audit, Audiences,
  Branding, ClaimCreate, ClientRegistrations, Clients, Home, Metrics,
  ServiceAccounts, SystemUsers, TrustedProxies.
- Depois as demais páginas de carga (Settings, Claims, ClaimDetail,
  Client*, Database, OperatorTokens, Scope*, Sessions, Authorizations, Users e
  as páginas de usuário) e o `RegistrationTokenPanel`.
- Ficaram como estavam: os erros de envio de formulário em todas as páginas;
  Provisioning e ScopeCreate (só têm envio); a subcarga de configuração do
  Metrics, que divide a área de mensagem com o salvar; MainLayout/NavMenu, que
  usam o overview só como indicador.

## Defeitos corrigidos no caminho

- ClientRegistrations: carga com falha mostrava o esqueleto para sempre.
- ServiceAccounts: carga com falha aparecia como "nenhuma conta de serviço".
- ClaimCreate: falha ao carregar usuários desligava o envio sem explicação.
- OperatorTokens e TrustedProxies: não havia como tentar de novo.
- Users: qualquer falha da carga de acesso aparecia como "acesso ao diretório
  não autorizado", inclusive o backend fora do ar.

## Números

- 23 testes bUnit novos (`ManagementDataViewTests`); `bunit 2.11.3` entrou no
  projeto de testes. Suíte: 1860 passando, 2 ignorados de propósito.
- 33 chaves de recurso que nada usa mais saíram; 10 `Common.State.*` entraram.
- UI: 948 linhas apagadas, 637 acrescentadas (o componente tem 219).
  Branding 940 → 931, UserDetail 336 → 312, Clients 609 → 592: o grosso do
  tamanho dessas páginas não era a duplicação de estados.
- O "tentar de novo" de Branding, Home, Settings e Metrics deixou de ser
  primário e ficou no estilo secundário de todas as outras.
