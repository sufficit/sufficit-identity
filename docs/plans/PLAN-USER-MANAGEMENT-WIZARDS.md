# Plano — ações de usuário em fluxos dedicados

Atualizado em: 2026-09-22 12:51 BRT

Objetivo: reduzir a tela de detalhe do usuário a um resumo limpo e mover cada operação sensível para uma rota própria, adequada a dispositivos móveis e organizada como um fluxo de uma função por vez.

## Execução

- [x] Confirmar o problema na captura e mapear os fluxos existentes.
- [x] Definir as rotas e a navegação compacta sem alterar as regras de autorização.
- [x] Implementar o seletor recolhível, as páginas dedicadas e o motivo de MFA em uma linha.
- [x] Atualizar testes de rota e navegador; validar desktop, mobile, acessibilidade e build.
- [x] Revisar o diff, registrar decisões e preparar a mudança para integração.
- [x] Publicar a revisão aprovada em produção e verificar os três nós.

Plano concluído. Entrega registrada em `docs/activities/202609221251-user-management-action-wizards.md`.

## Ajuste responsivo — 2026-09-22

- [x] Confirmar na nova captura que o seletor recolhível também estava sendo usado em telas largas.
- [x] Exibir as quatro ações lado a lado quando houver largura e reservar o toggle para resoluções compactas.
- [x] Atualizar o teste de navegador para validar desktop aberto por padrão e mobile recolhido.
- [ ] **Em andamento:** integrar, publicar e verificar os três nós.

## Decisões

- A tela de detalhe continua sendo o ponto de consulta do usuário e passa a mostrar apenas um botão compacto para as operações extras.
- O botão alterna um seletor de ações sem reservar espaço quando fechado.
- MFA, acesso, senha e exclusão usam URLs próprias e uma única tarefa por página.
- Autorizações, exigência de MFA recente, auditoria e confirmações existentes permanecem inalteradas.
- O motivo da redefinição de MFA usa um campo de texto de uma linha, mantendo os limites de 10 a 500 caracteres.

## Referências

- Captura fornecida pelo usuário em `tmp/paste-49e09dff38928f4a.png`.
- Preferência explícita do usuário por uma função por tela, URL própria e fluxo tipo wizard.
- Componentes e estilos atuais de `Sufficit.Identity.UI.Management` e `Sufficit.Blazor.UI`.
- Regras de composição, adaptação e redução de ruído das skills Refero Design e Impeccable.

## Validação exigida

- Testes de renderização das rotas de gerenciamento.
- Testes unitários e de integração do repositório.
- Fluxo real no navegador em viewport desktop e móvel.
- Detector de qualidade visual da skill Impeccable.
- Verificação pós-publicação de revisão, saúde, certificado e JWKS.
