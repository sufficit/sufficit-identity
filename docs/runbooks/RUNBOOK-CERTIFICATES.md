# Runbook — Certificados de Token (assinatura e encriptação)

> **Status:** ACTIVE. Criado 2026-08-16 após investigação de incompatibilidade PFX.
> Cobertura: geração, deploy, rotação e troubleshooting dos certificados X.509 que
> o Sufficit Identity usa para assinar (JWT/JWKS) e encriptar (JWE) tokens OAuth/OIDC.

## Visão geral

| Certificado | Arquivo | Função | Validade atual | CN |
|---|---|---|---|---|
| **Assinatura** | `certificate.pfx` | Assina JWTs, publica JWKS | Ver `openssl` | `sufficit-identity-signing` |
| **Encriptação** | `certificate.pfx` *(compartilhado — ver M-4)* | Decripta access tokens JWE | Idem | Idem |
| **Vault KEK** | `/etc/sufficit/identity/vault-kek.pfx` | Protege key-ring do vault | ~10 anos | `sufficit-identity-vault-kek` |

## ⚠️ DESCULPA IMPORTANTE — Incompatibilidade PFX

**O runtime .NET 10.0.10 em produção (`/opt/dotnet-10/`) REJEITA PFX files que não
o cert original**, independentemente da senha ou do formato. Isto foi descoberto
em 2026-08-16 após 6 tentativas de deploy de um cert de encriptação separado.

### O que NÃO funciona (testado e confirmado)

| Método de geração | Resultado no server |
|---|---|
| `openssl req` + `openssl pkcs12 -export` (qualquer combinação de `-certpbe`, `-keypbe`, `-macalg`) | ❌ "password may be incorrect" |
| .NET SDK `CertificateRequest.CreateSelfSigned()` + `Export(Pkcs12)` rodando com SDK 10.0.302 | ❌ "password may be incorrect" |
| Qualquer PFX com senha diferente da senha do cert original | ❌ "password may be incorrect" |

### O que FUNCIONA

| Método | Contexto |
|---|---|
| O `certificate.pfx` **original** (método de geração desconhecido) | Sempre funcionou em produção |
| .NET SDK `Export(Pkcs12)` → carregado pelo **mesmo SDK** localmente | Round-trip OK |

### Hipótese

O runtime-only 10.0.10 aplica `Pkcs12LoaderLimits` mais restritivos que o SDK
10.0.302. O cert original foi gerado antes desses limites ou por uma ferramenta
que produz uma estrutura PKCS#12 específica que passa nos limites.

## Processo recomendado para gerar um novo certificado

### Opção A (RECOMENDADA) — Gerar no próprio server

Adicionar um comando CLI ao `Sufficit.Identity.Server.dll`:

```bash
# No server (usa o MESMO runtime que vai carregar o cert):
/opt/dotnet-10/dotnet Sufficit.Identity.Server.dll --generate-encryption-cert \
    --output /opt/sufficit-identity/certificate-encryption.pfx \
    --password "SENHA_NOVA"
```

Isto garante compatibilidade **por construção** — o cert é gerado pelo mesmo
runtime que vai carregá-lo.

**Implementação:** adicionar ao `Program.cs`:
```csharp
if (args.Contains("--generate-encryption-cert"))
{
    // parse --output e --password dos args
    var rsa = RSA.Create(3072);
    var request = new CertificateRequest(
        "CN=sufficit-identity-token-encryption",
        rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    // ... extensions ...
    using var cert = request.CreateSelfSigned(
        DateTimeOffset.UtcNow.AddMinutes(-5),
        DateTimeOffset.UtcNow.AddYears(10));
    File.WriteAllBytes(outputPath, cert.Export(Pkcs12, password));
    return;
}
```

### Opção B (WORKAROUND) — Publicar um gerador self-contained

```bash
# Localmente:
dotnet publish -c Release -r linux-x64 --self-contained -o /tmp/cert-gen
scp /tmp/cert-gen/cert-gen root@server:/tmp/

# No server:
/tmp/cert-gen  # gera e salva o PFX
```

**Atenção:** o self-contained binary precisa incluir TODAS as dependências
(`--self-contained true`). Um publish dependente de framework não funciona
no server (que não tem SDK).

### Opção C (NÃO RECOMENDADA) — Descobrir o formato do cert original

```bash
# No server, extrair a estrutura interna do cert que funciona:
openssl pkcs12 -in /opt/sufficit-identity/certificate.pfx \
    -passin pass:"$SIGNING_PASSWORD" -info -nokeys 2>&1

# Comparar com o PFX que não funciona:
openssl pkcs12 -in /tmp/certificate-encryption.pfx \
    -passin pass:"$ENCRYPTION_PASSWORD" -info -nokeys 2>&1
```

Isto é frágil: a diferença pode ser em qualquer atributo ASN.1 e pode mudar
entre versões do runtime.

## Deploy de um novo certificado

### 1. Assinatura (rotação)

```bash
# Gerar novo cert (ver opções acima)
# Copiar para o server:
scp certificate-new.pfx root@server:/opt/sufficit-identity/

# Configurar overlap (o cert antigo fica publicado no JWKS durante a janela):
# appsettings.Production.json:
#   "SigningPaths": ["certificate.pfx", "certificate-new.pfx"]
#   "SigningPath": "certificate-new.pfx"        ← novo é o ativo
#   "SigningPassword": "senha-do-novo"

# Atualizar vault-secrets:
# SUFFICIT_SECRET_IDENTITY_CERTIFICATES_SIGNING_PASSWORD=nova_senha

# Restart:
systemctl restart sufficit-identity
```

### 2. Encriptação (novo cert)

```bash
# Após gerar o cert (ver opções acima):
scp certificate-encryption.pfx root@server:/opt/sufficit-identity/

# Config:
# appsettings.Production.json:
#   "EncryptionPath": "certificate-encryption.pfx"
#   "RequirePurposeSeparation": true

# vault-secrets:
# SUFFICIT_SECRET_IDENTITY_CERTIFICATES_ENCRYPTION_PASSWORD=senha_encryption

# Restart:
systemctl restart sufficit-identity
```

### 3. Vault KEK

```bash
# O KEK já existe (10 anos, CN=sufficit-identity-vault-kek):
ls -la /etc/sufficit/identity/vault-kek.pfx

# Para trocar:
# 1. Gerar novo KEK
# 2. Re-encriptar todos os DEKs (o vault faz isso automaticamente na rotação)
# 3. Atualizar vault-secrets + config
```

## Troubleshooting

### Erro: "The certificate data cannot be read with the provided password"

**Causa raiz:** Ver [investigação completa](../activities/202608161930-pfx-encryption-cert-investigation.md).

1. Verificar que a senha está correta:
   ```bash
   # No server:
   source /etc/sufficit/identity/vault-secrets.env
   openssl pkcs12 -in /opt/sufficit-identity/certificate.pfx \
       -passin pass:"$SUFFICIT_SECRET_IDENTITY_CERTIFICATES_SIGNING_PASSWORD" \
       -nokeys -clcerts | openssl x509 -noout -subject
   ```

2. Se o openssl carregar mas o .NET não → **incompatibilidade de formato PFX**
   (o cert foi gerado por ferramenta incompatível com o runtime)

3. **Solução:** gerar o cert com uma das opções acima (A ou B)

### Erro: "No signing certificate configured"

O cert está faltando ou o caminho no config está errado:
```bash
grep -E "SigningPath|EncryptionPath" /opt/sufficit-identity/appsettings.Production.json
ls -la /opt/sufficit-identity/*.pfx
```

### Erro: "Certificate purpose separation requires different active signing and encryption certificates"

`RequirePurposeSeparation=true` mas os thumbprints são iguais (mesmo arquivo):
```bash
openssl pkcs12 -in /opt/sufficit-identity/certificate.pfx -passin pass:"SENHA" \
    -nokeys -clcerts | openssl x509 -noout -fingerprint -sha256
openssl pkcs12 -in /opt/sufficit-identity/certificate-encryption.pfx -passin pass:"SENHA" \
    -nokeys -clcerts | openssl x509 -noout -fingerprint -sha256
# Devem ser DIFERENTES
```

## Boas práticas

1. **Sempre gerar no server** (ou com self-contained) — nunca com OpenSSL CLI
2. **Separar certificados por propósito** — assinatura ≠ encriptação ≠ KEK
3. **Validade ≥ 10 anos** para evitar rotação frequente
4. **RSA-3072 mínimo** (compatível com FAPI 2.0 se combinado com PS256/ES256)
5. **Senha diferente por certificado** — a senha do vault-secrets é por cert
6. **Backup dos certs + senhas** em local seguro (não no repo)
7. **Overlap na rotação de assinatura** — usar `SigningPaths` (array) para manter
   o cert antigo no JWKS durante a janela de transição

## Estado atual (2026-08-16)

- ✅ Cert de assinatura funcionando (arquivo único compartilhado com encriptação)
- ⏳ Cert de encriptação separado: **bloqueado** pela incompatibilidade PFX
  (`certificate-encryption.pfx` RSA-3072/10-anos já deployado nos 3 servers)
- ✅ Vault KEK separado (10 anos, `vault-kek.pfx` em `/etc/sufficit/identity/`)
- ❌ `RequirePurposeSeparation`: `false` (rollback aplicado durante investigação)

## Referências

- [Investigação PFX completa](../activities/202608161930-pfx-encryption-cert-investigation.md)
- [Triagem Fable-5 — M-4](../plans/PLAN-FABLE-5-TRIAGE.md)
- [OpenIddict docs — Signing credentials](https://documentation.openiddict.com/configuration/token-credentials.html)
- [RFC 7517 — JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
