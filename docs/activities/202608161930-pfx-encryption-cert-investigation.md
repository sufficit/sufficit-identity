# Investigação: PFX de encriptação separado — achados e solução pendente

> **Data:** 2026-08-16
> **Contexto:** Avaliação Fable-5 M-4 (cert compartilhado signing+encryption)
> **Status:** Pendente — serviço estável com cert único; separação requer método correto

## O que foi tentado e os resultados

| Tentativa | Método | Resultado local (.NET 10.0.302 SDK) | Resultado server (.NET 10.0.10 runtime) |
|---|---|---|---|
| v1 | `openssl pkcs12 -export` padrão | Não testado | ❌ "password may be incorrect" |
| v2 | `openssl pkcs12 -export` com `-certpbe AES-256-CBC -keypbe AES-256-CBC -macalg sha256` | Não testado | ❌ "password may be incorrect" |
| v3 | `openssl pkcs12 -export` com senha = signing | Não testado | ❌ "password may be incorrect" |
| v4 | .NET `CertificateRequest.CreateSelfSigned()` + `Export(Pkcs12)` senha nova | ✅ Round-trip OK | ❌ "password may be incorrect" |
| v5 | .NET `CertificateRequest.CreateSelfSigned()` + `Export(Pkcs12)` senha production | ✅ Round-trip OK | ❌ "password may be incorrect" |
| v6 | Password hardcoded no appsettings | N/A | ❌ (rejeitado pelo `EnsureNoPlaintextSecrets` — teste inválido) |
| Original `certificate.pfx` | ??? (método desconhecido) | ❌ (não sabemos a senha) | ✅ Funciona em produção |

## Diagnóstico

### Confirmado por testes

1. **OpenSSL 3.x PFX ≠ .NET 10 runtime compatível.** O `X509CertificateLoader.LoadPkcs12FromFile`
   do .NET 10.0.10 (runtime do servidor) rejeita **qualquer** PFX gerado por `openssl pkcs12 -export`,
   independente de senha ou parâmetros (`-certpbe`, `-keypbe`, `-macalg`).

2. **.NET SDK ≠ .NET runtime (server).** O .NET 10.0.302 **SDK** (local) carrega .NET-generated PFX
   perfeitamente em round-trip. O .NET 10.0.10 **runtime** (server) rejeita o MESMO arquivo.

3. **Openssl CLI no server carrega TODOS os PFX.** A senha está correta (verificada por hex dump),
   o arquivo é válido, a ferramenta openssl consegue extrair cert+chave sem erro.

4. **O `certificate.pfx` original funciona.** O cert de assinatura em produção carrega perfeitamente
   no .NET runtime do server. O método de geração deste cert é **desconhecido** — não foi OpenSSL
   (visto o item 1) nem .NET SDK (visto o item 2). Possivelmente foi gerado por:
   - Uma versão anterior do runtime .NET
   - `dotnet dev-certs` (que gera certs de dev compatíveis)
   - Uma ferramenta Windows/PowerShell (`New-SelfSignedCertificate` + Export)
   - O script `deploy/gen-cert.sh` do repo (usa openssl — MAS ver item 1)

5. **A entrega da senha NÃO é o problema.** Verificado por:
   - Hex dump do `vault-secrets.env` (senha correta, sem caracteres invisíveis)
   - `systemd-run` com `EnvironmentFile` → env var presente e correta
   - Hardcode no appsettings → também falha (mas foi rejeitado por plaintext-check)
   - `opensl pkcs12` no server com a mesma senha → funciona

### Hipótese mais provável

O **runtime .NET 10.0.10** (server) tem um `Pkcs12LoaderLimits` ou parser PKCS#12 diferente
do .NET 10.0.302 (SDK local). Especificamente, o runtime pode estar aplicando limites
mais restritivos (parte do hardening de .NET 10 para PKCS#12) que rejeitam estruturas
geradas tanto por OpenSSL 3.x quanto pelo `Export()` do SDK.

O cert original foi provavelmente gerado em um momento anterior a esses limites, ou
com uma versão/ferramenta que produz uma estrutura que passa nos limites.

## Root cause a investigar

```bash
# Verificar a versão exata do runtime:
ls /opt/dotnet-10/shared/Microsoft.NETCore.App/
# → 10.0.10 (runtime)

# O SDK local:
dotnet --version
# → 10.0.302 (SDK = runtime 10.0.10 + SDK tooling)

# HIPÓTESE: o cert original foi gerado pelo SDK 10.0.302 com Export()
# mas em um contexto diferente (ex: com X509KeyStorageFlags específicos,
# ou sem BasicConstraintsExtension, ou com um CertificateRequest diferente)
```

## Próximos passos recomendados

1. **Verificar `deploy/gen-cert.sh`** — se este script gerou o cert original, entender como
   (ele usa openssl, mas talvez uma versão mais antiga que produzia PFX compatível).

2. **Testar com runtime-only no local** — instalar apenas o runtime 10.0.10 localmente
   e verificar se o .NET-generated PFX também falha. Isto confirmaria que a diferença
   é runtime vs SDK.

3. **Testar o cert original com a senha localmente** — obter a senha de dev
   (se o cert de deploy/local/ foi gerado com senha conhecida) e tentar carregar
   localmente com .NET. Se carregar, gerar o novo cert com o MESMO setup.

4. **Usar o próprio aplicativo para gerar o cert** — adicionar um comando CLI ao
   Sufficit.Identity.Server (ex: `--generate-encryption-cert`) que gera e salva o
   cert usando o MESMO runtime que vai carregá-lo. Isto garante compatibilidade
   por construção.

5. **Wrapper no server** — gerar o cert DIRETO no server usando `/opt/dotnet-10/dotnet`
   com um script C# simples compilado via `csc` (se disponível no runtime) ou via
   self-contained single-file publish.

## Estado atual (2026-08-16 19:30 UTC)

- ✅ 3/3 servers Healthy com `None:false` + CSP `'self'` (sem wildcards)
- ⚠️ `deploy/local/appsettings.json` corrigido (None:false, CSP limpo)
- ❌ Cert de encriptação ainda compartilhado com signing (rollback aplicado)
- 📁 `certificate-encryption.pfx` (.NET-generated, 10 anos, RSA-3072) presente nos
  3 servers em `/opt/sufficit-identity/` — pronto para quando o método correto
  de geração for identificado
