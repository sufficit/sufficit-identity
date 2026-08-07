# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

- Pessoas que autenticam em aplicações Sufficit e de terceiros. Em geral chegam
  por redirecionamento, querem concluir a autenticação rapidamente e podem estar
  em dispositivos móveis ou conexões lentas.
- Operadores do provedor que receberam capabilities administrativas explícitas.
  Eles configuram o runtime, clientes e scopes e inspecionam identidades, sessões,
  autorizações, auditoria e saúde operacional.

## Product Purpose

Sufficit Identity é um provedor OAuth 2.0/OpenID Connect auto-hospedável sobre
.NET, OpenIddict e ASP.NET Core Identity. Ele fornece superfícies públicas de
autenticação e uma console administrativa segura. Sucesso significa autenticação
rápida e confiável para o usuário final e operação precisa, auditável e acionável
para o operador.

## Positioning

O produto combina cobertura moderna de protocolos de identidade com um contrato
de aplicação independente do adaptador: UI embutida e API HTTP executam os mesmos
casos de uso, sem duplicar regras ou acessar persistência diretamente.

## Operating Context

O runtime roda atrás de proxy reverso e usa MySQL/MariaDB em produção. A Management
UI é uma ferramenta operacional de uso deliberado: operadores investigam estado,
configuram recursos e respondem a incidentes. Liveness, readiness, logs, métricas
de pool e supervisão do processo fazem parte da operação do serviço.

## Capabilities and Constraints

- A persistência principal é o `AppDbContext`; o provedor de produção atual é
  MySQL/MariaDB, enquanto testes usam SQLite.
- A observabilidade de banco deve manter contratos agnósticos de provedor e pode
  enriquecer os dados por adaptadores específicos quando o driver oferecer métricas.
- A console não pode expor credenciais, connection strings, SQL, parâmetros,
  payloads de tokens ou outros dados sensíveis.
- O acesso administrativo é controlado por capabilities; papéis de negócio do
  ecossistema Sufficit não pertencem ao modelo genérico do provedor.
- UI e API chamam o mesmo serviço de aplicação; a UI não acessa `DbContext`,
  ASP.NET Identity ou gerenciadores OpenIddict diretamente.
- O runtime precisa limitar espera, tamanho e vida útil do pool e recuperar-se de
  degradação persistente do banco sob controle do supervisor do processo.
- Métricas de uso nunca podem bloquear autenticação; coleta e exportação operam
  em filas limitadas, com descarte observável e configuração persistida no banco.

## Brand Commitments

Nome: Sufficit Identity. Voz em português brasileiro, concisa e formal-adjacente.
Personalidade: profissional, segura e direta. A marca usa vermelho Sufficit com
restrição; estados operacionais nunca dependem apenas de cor. Os ativos existentes
e o sistema visual documentado em `docs/design/` são a autoridade da interface.

## Evidence on Hand

- Diagnóstico do incidente legado:
  `/mnt/sufficit/sufficit-identity-legacy/docs/202608042100-production-resilience.md`.
- Implementação e captura da tela legada de conexões em
  `/mnt/sufficit/sufficit-web/src/WebUserControls/WUCConexoes.ascx` e no anexo
  fornecido pelo usuário.
- Definição de produto, sistema visual e arquitetura em `docs/design/` e
  `docs/architecture/`.
- O runtime fornece dados reais; a interface não deve fabricar demonstrações,
  indicadores ou garantias de disponibilidade.

## Product Principles

1. Uma única fonte de verdade em runtime para UI e API.
2. Segurança demonstrada por limites, clareza e ausência de exposição sensível.
3. Estado operacional acionável, com falhas e pressão de capacidade visíveis.
4. Recuperação automática somente após degradação persistente e verificável.
5. Desempenho e acessibilidade são requisitos de confiabilidade.

## Accessibility & Inclusion

WCAG 2.2 AA é o piso. Toda ação deve funcionar por teclado, o foco precisa ser
visível, estados devem combinar texto/estrutura com cor, movimento deve respeitar
`prefers-reduced-motion` e layouts devem acomodar strings maiores e telas móveis.
