# Núcleo de autorização para integração de sistemas parceiros

## Objetivo e estado inicial

Implementar e simular localmente a primeira etapa da autenticação de um backend
parceiro, com usuário humano separado, credencial anual e token de acesso curto.
Sem cadastro produtivo, implantação, alterações de PABX ou código específico de
um parceiro.

Base: commit `637c35b`, branch `main` do `sufficit-identity`. A árvore principal
continha alterações alheias em arquivos de lock de pacotes; foram preservadas.
Entrega isolada em `.worktrees/partner-auth-core`, branch
`feat/partner-auth-core`.

O núcleo já tinha emissão `client_credentials`, entitlements por aplicação,
registro de credenciais adicionais, validade e revogação. A primeira credencial
para um cliente público era obrigada a usar o campo legado sem datas.

## Alterações

- `ClientCredentialRegistry`: a primeira credencial com `notBeforeUtc` ou
  `expiresAtUtc` usa o registro gerenciado, promove o cliente a confidencial e
  não grava segredo no campo legado. Registro, auditoria e promoção compartilham
  a transação existente. A primeira credencial sem datas mantém a compatibilidade.
- `SufficitOpenIddictApplicationManager`: reconhece o registro persistido como
  fonte de credencial na validação da aplicação. Somente o diagnóstico de
  ausência de segredo/chave `ID2113` é dispensado nesse caso; as demais regras
  permanecem. A autenticação continua consultando validade/revogação e hash.
- `PartnerAuthorizationSimulationTests`: sete casos com SQLite em memória e
  autorização real, usuário fictício, aplicação, emissão HTTP, validação
  criptográfica por JWKS, negativas de gestão e de alteração pelo próprio
  parceiro, rotação e ciclo de vida.
- [Guia de uso](../usage/USAGE-PARTNER-SYSTEM-AUTHORIZATION.md): exemplos de
  cadastro em três etapas, comunicação, renovação, revogação e limites.

A adaptação usa o diagnóstico publicado pelo
[manager do OpenIddict 7.7](https://github.com/openiddict/openiddict-core/blob/7.7.0/src/OpenIddict.Core/Managers/OpenIddictApplicationManager.cs).
Sua correspondência usa o recurso localizado da própria biblioteca, não uma
mensagem em inglês codificada. Upgrades do OpenIddict devem manter os testes da
credencial inicial e da rejeição de outras configurações inválidas.

Nenhuma tabela, migração, capability administrativa ou modelo de carteira foi
adicionado. A tabela de credenciais existente precisa estar migrada no ambiente
que futuramente receber esta versão.

## Decisões

O segredo anual é uma credencial da aplicação. O access token da simulação dura
15 minutos e identifica a aplicação em `sub`; não personifica o administrador
humano nem herda suas permissões. Renovação significa outra chamada
`client_credentials`, não refresh token. A configuração de 15 minutos foi
aplicada ao cliente fictício, sem mudar o padrão global do servidor.

Os entitlements de negócio foram concedidos explicitamente pela fixture
interna. Não existe nesta entrega um novo cadastro de carteira ou delegação
automática. Identificadores e nomes fictícios são gerados nos testes.

Revogar/vencer o segredo bloqueia novas emissões. JWTs anteriormente emitidos
não são invalidados por essa operação e precisam de expiração ou de um mecanismo
adicional efetivamente consumido pela API.

## Validação

SDK `10.0.302`, modo NuGet (`SufficitUseLocalSui=false`).

- Baseline do caminho legado da primeira credencial: 1 teste aprovado.
- Suíte focada de clientes, credenciais, entitlements, contas de serviço,
  autorização de gestão e simulação: 97 testes aprovados, sem warnings.
- Suíte completa final, incluindo a negativa de criação de credencial pelo
  próprio parceiro: **1092 aprovados, zero falhas, zero warnings**, 14,3 segundos.

```bash
dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore \
  -p:SufficitUseLocalSui=false -p:TreatWarningsAsErrors=true \
  --logger 'trx;LogFileName=partner-auth-suite.trx'
```

Executado pelo wrapper `rtk dotnet test`. `git diff --check` também passou.

A primeira execução encontrou a exigência do segredo legado no OpenIddict,
resolvida pela adaptação descrita acima. Um teste inicialmente exigia
`expires_in=900` exato; foi corrigido para aceitar o tempo remanescente na
serialização, mantendo a verificação exata de `exp - iat = 900` no token assinado.

## Limites e entrega

Código e documentação entregues em branch local; sem push, merge ou deploy.
Não foi criada credencial reutilizável em produção. Tokens/segredos foram
emitidos apenas nos testes e descartados ao encerrar as fixtures.

A simulação prova a emissão das concessões e a negativa de gestão global.
Ainda não prova autorização de uma chamada real à API de telefonia, vínculo de
carteira, histórico, provisionamento de ramal nem áudio SIP/WebRTC. Esses são
os próximos incrementos documentados no guia. Segregação de discagem interna
continua adiada conforme a prioridade definida pelo usuário.
