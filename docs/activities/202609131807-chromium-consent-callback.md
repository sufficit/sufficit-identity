# Callback Chromium após consentimento OAuth

## Objetivo

Corrigir o fluxo interativo da extensão Chrome que terminava com
`Authorization page could not be loaded` depois de o usuário aprovar o
consentimento no Identity.

## Diagnóstico

Os journals de produção mostraram duas aprovações de consentimento para o
cliente `SufficitChromeExtension`, ambas com cinco escopos, seguidas por uma
violação CSP da diretiva `form-action`. Portanto, o servidor reconhecia o
login e aprovava o consentimento; o navegador interrompia a cadeia de
redirecionamentos entre o POST para `/connect/authorize` e o callback
`https://<extension-id>.chromiumapp.org/`.

O comportamento é consistente com a aplicação de `form-action` por Chromium
a toda a cadeia iniciada pelo envio do formulário. A política anterior
permitia apenas `'self'`, embora o destino terminal legítimo fosse externo.

## Implementação

`SecurityHeadersMiddlewareExtensions` agora amplia `form-action` na página
`/consent` somente quando:

1. `client_id` e `redirect_uri` estão presentes;
2. o URI é HTTP(S), absoluto e sem informações de usuário;
3. o cliente existe no registro OpenIddict; e
4. o URI solicitado pertence exatamente à lista de callbacks desse mesmo
   cliente.

A política recebe apenas o caminho HTTP(S) validado, sem query string ou
fragmento. URLs arbitrárias e callbacks registrados para outro cliente não
ampliam a CSP. A regra existente de logout foi preservada.

Foram adicionados testes de integração para o callback registrado, URI não
registrado e tentativa de usar o callback de outro cliente.

## Validação

```bash
dotnet test src/tests/Sufficit.Identity.Tests.csproj \
  --filter FullyQualifiedName~CspHeaderTests -c Release --no-restore
dotnet format Sufficit.Identity.sln --verify-no-changes --no-restore \
  --include src/sts/SecurityHeadersMiddlewareExtensions.cs \
  src/tests/CspHeaderTests.cs
dotnet build Sufficit.Identity.sln -c Release --no-restore
dotnet test src/tests/Sufficit.Identity.Tests.csproj \
  -c Release --no-build --no-restore
git diff --check
```

Resultados:

- 20 testes CSP aprovados;
- formatação sem alterações;
- 17 projetos compilados, zero erros;
- 1.299 testes aprovados, zero falhas;
- `git diff --check` aprovado.

O build manteve uma advertência `CS8604` preexistente em
`ClientEdit.razor:884`, fora do escopo desta correção.

## Estado da entrega

Durante a validação, o commit concorrente `c346be6` incorporou a correção e os
testes ao branch `main` e a `origin/main`, junto de uma refatoração do host que
já estava em andamento. Para não publicar essa refatoração e outras mudanças
acumuladas, a correção foi reconstruída sobre a revisão anterior de produção e
publicada como hotfix `d35f6bc`; os detalhes, verificações e rollback estão em
[202609131833-deploy-chromium-consent-callback.md](202609131833-deploy-chromium-consent-callback.md).
