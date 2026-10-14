# Deploy da página amigável de device code

Objetivo: publicar a correção validada nos três nós Identity, em sequência, pelos helpers oficiais, preservando configuração e certificados.

1. CONCLUÍDO — Conferir estado dos nós e validar build/testes com SUI local; registrar revisão local da correção.
2. EM ANDAMENTO — Empacotar revisão limpa e preparar o mesmo arquivo nos três nós.
3. PENDENTE — Ativar sequencialmente, conferir health/ready, revisão, certificados e JWKS.
4. PENDENTE — Conferir superfície pública e registrar entrega.

Sem mudança de banco nesta correção; conferir baseline antes da ativação. Não há autorização adicional necessária para este deploy solicitado pelo usuário.
Validação: testes direcionados, package-release.sh, prepare-cluster-release.sh, activate-cluster-release.sh e verificação HTTP pública.

Baseline: três nós ativos em 7bd6c48. Testes com SUI local: 65 passaram; cinco avisos de auditoria NuGet em dependências transitivas Pkcs/Xml 10.0.11. Sem alteração de dependências nesta tarefa.
