# Escrow da KEK do Vault por backup diário do apoint-apps (C1, 23/10/2026)

A KEK do Vault (`/etc/sufficit/identity/vault-kek.pfx`) e a senha dela
(`SUFFICIT_SECRET_VAULT_KEK_CERTIFICATE_PASSWORD`, em `vault-secrets.env`) são
idênticas nos três nós `*-apps` (mesmo sha256 do arquivo e da linha da senha).
Uma cópia de um nó basta.

Decisão do titular: em vez de um cofre à parte, backup diário do CT do
`apoint-apps` no Proxmox.

- Job PVE `bdb18c8f-8000-40df-b34f-3d6af344f8a2`: CT 1101, diário 02:30,
  snapshot, zstd, storage `nas-sufficit` (TrueNAS da Acesso Point),
  `keep-daily=7,keep-weekly=4`, e-mail em falha para `daily@`.
- `tmpdir /var/tmp`: o CT é não-privilegiado e o `tar` (uid mapeado) não
  escreve o diretório temporário no NFS — a primeira execução falhou com
  `Permission denied` por isso.
- Primeira cópia: `vzdump-lxc-1101-2026_10_23-18_36_44.tar.zst`, 9,4 GB; lida
  inteira sem erro e contém `vault-kek.pfx` e `vault-secrets.env`.

Para restaurar o Vault num servidor novo: extrair esses dois arquivos do dump
(`tar -I zstd -xf ... ./etc/sufficit/identity/vault-kek.pfx
./etc/sufficit/identity/vault-secrets.env`) e seguir `RUNBOOK-VAULT.md`.

Observação: arquivo e senha ficam no mesmo backup; quem lê o NAS tem os dois.
O item "separar quem lê o banco de quem tem a KEK" segue no plano.
