# Consolidação das atualizações pendentes

Pedido explícito: merge de todos os trabalhos pendentes na main e sincronia remota.

Integrados os sete PRs Dependabot abertos: Actions CodeQL/upload, adaptador NUnit, NUnit 5, pacotes Microsoft/EF10.0.13 e OpenIddict. Conflitos em dependências foram conciliados pelo catálogo central e locks regenerados com restore --force-evaluate, sem remover o modo locked do CI.

A suíte reproduziu uma falha de contrato do SQL gerado (1690 passaram, uma falha, um skip): metadados ProductVersion10.0.11 divergiam do EF10.0.13. Regenerado o script pelo comando oficial de docs/migration/README.md. Diff limitado a26 registros de ProductVersion; nenhuma migração foi executada em banco. Repetição:1691 testes passaram, um skip de integração NATS existente. Logs em /tmp/sufficit-consolidation-identity-*. O build e a geração do SQL concluíram; ferramenta EF10.0.11 emitiu aviso por ser anterior ao runtime10.0.13.

Branches históricas com ancestralidade reescrita foram preservadas, sem importar versões antigas sobre a main atual. Atividade local da ponte IA preservada nesta integração. Nenhum deploy manual.
