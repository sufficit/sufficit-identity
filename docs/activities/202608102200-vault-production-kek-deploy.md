# Vault — certificado KEK dedicado em produção

**Data:** 2026-08-10 22:00 (America/Sao_Paulo)  
**Release:** `1d0fb57`  
**Escopo:** eveo-apps, apoint-apps e castrum-apps

## Entregue

- Gerado um PFX autoassinado dedicado ao Vault, com chave privada RSA-4096 e
  validade de 825 dias. O material não foi commitado; a cópia operacional local
  fica em `deploy/local/`, ignorada pelo Git.
- Instalado o mesmo PFX em
  `/etc/sufficit/identity/vault-kek.pfx` nos três nós, com proprietário
  `root:www-data` e modo `0640`.
- Provisionado o segredo separado
  `SUFFICIT_SECRET_VAULT_KEK_CERTIFICATE_PASSWORD` em
  `/etc/sufficit/identity/vault-secrets.env`, também `root:www-data:0640`.
- Configurado `Sufficit__Vault__CertificatePath` para o caminho persistente do
  host. O certificado de assinatura do STS não foi substituído nem reutilizado.
- Corrigido o validador `check-vault-secrets.sh` para aceitar o nome de segredo
  já definido no mapeamento `ISecretStore`, com cobertura de regressão.

## Validação

- O rollout foi executado por `helpers/activate-cluster-release.sh`, com lease
  de cluster e rollback automático. A primeira tentativa foi revertida por uma
  pendência pré-existente de CSP Report-Only; após registrar a confirmação de
  compatibilidade, a segunda tentativa concluiu nos três nós.
- `verify-production-cluster.sh` confirmou revisão uniforme, serviço ativo,
  `/health` e `/health/ready` saudáveis e os mesmos hashes de certificado/JWKS.
- O readiness do Vault registrou `Vault KEK dataprotection passed the startup
  readiness probe` em cada réplica.
- A chave do Vault foi validada como privada, RSA-4096 e com thumbprint
  diferente do certificado de assinatura do STS.

## Compatibilidade pendente

O CSP continua deliberadamente em Report-Only para não quebrar a UI durante a
calibração. Foram mantidos explicitamente:

```text
Sufficit__Identity__Csp__ReportOnly=true
Sufficit__Identity__Csp__AcknowledgeReportOnly=true
Sufficit__Identity__Security__AllowLegacyBooleanAcknowledgements=true
```

Essa ponte deve ser removida quando a política CSP for calibrada e aplicada em
modo enforce. A senha do PFX nunca deve ser registrada em evidências ou logs;
uma rotação futura precisa instalar o novo PFX e segredo em todas as réplicas
antes de ativar a versão que o referencia.
