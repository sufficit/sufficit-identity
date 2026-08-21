# Device flow em popup

O Genius usa o Device Authorization Grant (RFC 8628). Quando o cliente consegue
abrir uma janela controlada por script, ele acrescenta `launch_mode=popup` à
`verification_uri_complete`:

```text
https://identity.sufficit.com.br/connect/device?user_code=...&launch_mode=popup
```

O Identity preserva esse marcador durante o login, a aprovação/recusa e o
redirecionamento final para `/device`. A página final faz duas coisas quando
continua sendo um popup scriptável:

1. envia ao `window.opener` uma mensagem sem dados sensíveis;
2. tenta fechar a janela automaticamente.

Enquanto o marcador está presente, o cabeçalho `Cross-Origin-Opener-Policy`
usa `same-origin-allow-popups`. Isso é necessário para que a janela de origem
continue visível ao popup durante os redirecionamentos de login; as páginas que
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
  if (event.origin !== "https://identity.sufficit.com.br") return;
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
