# Launcher de Device Flow para abertura externa

O Symposium abria diretamente a verificação por openExternal. O Identity recebia opener=false e histórico com duas entradas, mantendo fechamento manual. Implementada página SSR anônima `/device/launch`, da mesma origem e política COOP do popup, para reservar o documento inicial e abrir a autenticação por clique.

O launcher aceita somente código curto validado e monta destino fixo `/connect/device`, sem tokens/URLs de retorno. Mensagens precisam ter origem, source, tipo, flow e resultado corretos. O popup e a aba inicial tentam fechar após aprovação/recusa; nenhuma mensagem substitui a busca OAuth do token. A interface PT/EN explica o fallback para popup bloqueado ou aba que recusa fechamento. Políticas globais de segurança não foram reduzidas.

Validação: suíte Identity com 1.179 testes aprovados; quatro testes de navegador dedicados aprovados no Chrome; build da solução em modo pacote com warnings como erros aprovado (16 projetos). Teste Chrome com HTML SSR dos testes + headers COOP reais + script real de conclusão confirmou fechamento de popup/launcher inicial para aprovação/recusa, rejeição de source inválido e fallback de popup bloqueado. Desktop/mobile PT/EN inspecionados; espaçamento ajustado reutilizando a classe de ações existente. Limitação confirmada: aba externa reutilizada com histórico pode recusar window.close e conserva mensagem manual.

Contrato: [Device Flow em popup](../design/DESIGN-DEVICE-FLOW-POPUP.md). Integração e deploy rastreados no plano ativo do Symposium. Este commit também consolida as alterações anteriores de proxies/snapshots/rate limit já autorizadas e publicadas nesta sessão, para que o fonte versionado corresponda à base produtiva; seus relatórios e testes estão em activities.
