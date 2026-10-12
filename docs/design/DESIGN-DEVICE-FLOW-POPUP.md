# Device flow em popup

O Genius usa o Device Authorization Grant (RFC 8628). Quando o cliente consegue
abrir uma janela controlada por script, ele acrescenta `launch_mode=popup` à
`verification_uri_complete`:

```text
https://identity.example.com/connect/device?user_code=...&launch_mode=popup
```

O Identity preserva esse marcador durante o login, a aprovação/recusa e o
redirecionamento final para `/device`. A página final faz duas coisas quando
continua sendo um popup scriptável:

1. envia ao `window.opener` uma mensagem sem dados sensíveis;
2. tenta fechar a janela automaticamente.

Enquanto o marcador está presente, o cabeçalho `Cross-Origin-Opener-Policy`
usa `same-origin-allow-popups`. As políticas precisam corresponder e a origem precisa ser a mesma para
preservar o opener entre documentos que usam esta diretiva; ela não garante
retenção de um opener de outra origem. As páginas que
não optam explicitamente por popup continuam usando `same-origin`.

Mensagem emitida:

```js
{
  type: "sufficit-auth-complete",
  flow: "device",
  result: "approved" // ou "denied"
}
```

O chamador deve validar `event.origin`, `event.source === popup` e o valor de
`result` antes de atualizar a própria UI. O payload não contém código de
dispositivo, token, identificador de usuário ou URL de retorno. O destino `*`
é usado apenas porque a janela de origem pode ser uma aplicação desktop ou uma
webview com outra origem; o controle de segurança fica na validação do
chamador.

Exemplo de abertura no Hermes ou em outra UI web:

```js
const popup = window.open(
  authUrlWithLaunchMode,
  "sufficit-auth",
  "popup,width=520,height=760,resizable=yes"
);

function onMessage(event) {
  if (event.origin !== "https://identity.example.com") return;
  if (event.source !== popup) return;
  if (event.data?.type !== "sufficit-auth-complete") return;

  window.removeEventListener("message", onMessage);
  if (event.data.result === "approved") {
    // Continue o polling do device flow ou atualize o estado do cliente.
  }
}

window.addEventListener("message", onMessage);
```

Se a autenticação for aberta por `xdg-open`, `open` ou um navegador já aberto,
o navegador pode não considerar a aba scriptável. Nesse caso o Identity não
força o fechamento: exibe a instrução de fechamento manual para não esconder
o resultado do usuário.

## Genius e abertura externa

Clientes desktop já instalados podem abrir
`/device/launch?user_code=...&launch_mode=popup`. Essa rota anônima redireciona
com HTTP 302 diretamente para `/connect/device?user_code=...&launch_mode=popup`
na mesma janela. Não renderiza uma página intermediária nem abre um popup filho.
Login e consentimento explícito seguem nos endpoints existentes.

A rota mantém `no-store`, `no-referrer` e COOP `same-origin-allow-popups`.
Aceita somente código público curto (até 64 caracteres ASCII alfanuméricos,
espaços e hífens) e monta um destino relativo fixo. Parâmetros adicionais,
incluindo URLs de retorno e device_code, não são repassados.

O polling OAuth do token no Genius continua sendo a autoridade para concluir
o login. O marcador `launch_mode=popup` permite a conclusão existente, mas
não torna uma aba aberta pelo sistema operacional scriptável: quando o
navegador recusa fechamento automático, a página final orienta o fechamento
manual. Essa limitação não exige outra janela de autenticação.

Clientes nativos que usam `launch_mode=app` e callback registrado continuam
usando seu fluxo direto, sem passar por essa rota de compatibilidade.
