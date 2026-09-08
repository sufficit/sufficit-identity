# SUI — consumo da versão corporativa

Objetivo: substituir a referência histórica 1.28.0 pela publicação Sufficit
1.26.908.2020, disponível no NuGet.org. Base de trabalho: ac07750.

Alterações: Directory.Packages.props e os seis lockfiles que contêm a SUI,
regenerados em modo pacote. A referência local por ProjectReference mantém
precedência quando há checkout irmão; CI continua em modo pacote/locked.

Validação: restore público com force-evaluate; restore locked-mode; build
Release da solução (16 projetos, zero avisos/erros); 189 testes de UI e
contratos documentais aprovados usando o pacote público. Os lockfiles
resolvem exatamente 1.26.908.2020, com hash do pacote assinado pelo NuGet.

Release SUI: https://www.nuget.org/packages/Sufficit.Blazor.UI/1.26.908.2020
Workflow de publicação: https://github.com/sufficit/sufficit-blazor-ui/actions/runs/34274199136
Esta atividade altera a dependência do repositório; não executa novo deploy
dos serviços Identity nem modifica políticas de autenticação.
