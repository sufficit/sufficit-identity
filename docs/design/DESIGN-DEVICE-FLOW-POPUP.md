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

## Symposium e abertura externa

O Symposium 2026.910.1 abre `/device/launch?user_code=...&launch_mode=popup`
quando o endpoint de verificação do Identity é `/connect/device`. O launcher é
uma página SSR anônima da mesma origem do Identity, com `no-store`,
`no-referrer` e COOP `same-origin-allow-popups`. Aceita somente o código curto
(até 64 caracteres ASCII alfanuméricos, espaços e hífens); não aceita URL de
retorno nem recebe device_code ou tokens.

Um clique em **Abrir autenticação** cria o popup de mesma origem. Esse clique
é necessário nos navegadores que bloqueiam popups sem interação. O launcher
permanece no documento inicial; a autenticação e seus redirecionamentos
acontecem no popup. Ao receber `sufficit-auth-complete`, valida origem exata,
janela emissora, flow e resultado approved/denied, fecha o popup e tenta fechar
a própria aba. O polling do token no Symposium continua sendo a autoridade
para concluir o login: uma mensagem do navegador nunca fornece credenciais.

No Chrome, a aba externa nova com uma entrada no histórico fecha junto com o
popup. Uma aba reutilizada com histórico anterior pode recusar o fechamento;
a página mantém o resultado e a orientação manual. Popup bloqueado oferece
**Continuar nesta aba**. Sem JavaScript, o link também continua diretamente e
exige fechamento manual. Fechar/reabrir o popup não cria novo device code.

O launcher foi testado com COOP real e o script de conclusão do Identity,
incluindo aprovação, recusa, mensagem de janela incorreta, popup bloqueado e
recusa de fechamento da aba. Autenticação externa federada que rompa a relação
opener pode exigir fallback; o launcher não reduz a política global para
`unsafe-none` nem contorna a segurança do navegador.
