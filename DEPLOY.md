# Sufficit Identity Deployment

Deploy do Sufficit Identity para os servidores de aplicação, seguindo o
padrão do `sufficit-endpoints` (script genérico `deploy.py` + `config.json`).

## 📁 Estrutura

```
sufficit-identity/
├── config.json          # Servidores, caminhos, exclusões persistentes
├── deploy.py            # Fork R018-identity do script genérico (R017):
│                        #   além de pastas, carrega ARQUIVOS persistentes
│                        #   (appsettings*, certificate*.pfx) para o staging
│                        #   antes do swap atômico
└── helpers/             # Scripts auxiliaros de instalação/migração
```

## 🚀 Como usar

```bash
# Publicar localmente (o irmão local do SUI é detectado e usado
# automaticamente — SEMPRE a versão mais recente):
dotnet publish src/server/Sufficit.Identity.Server.csproj \
    -c Release \
    -o publish-net10.0

# MIGRATIONS: o banco é MULTIMASTER replicado entre os 3 servers —
# rode o migrator UMA vez, em UM único server, ANTES do primeiro swap:
#    ssh <server> systemctl start sufficit-identity-migrator
#    ssh <server> journalctl -u sufficit-identity-migrator -n 5
# A replicação leva o schema aos demais; confira o lag antes de rolar os
# outros binários. A unit é estática (sem [Install]): nunca é habilitada
# em boot, sempre manual.

# Deploy staged (upload → stop → swap atômico → start → health):
python3 deploy.py eveo-apps
python3 deploy.py apoint-apps
python3 deploy.py castrum-apps
```

## 🔒 Regras específicas do Identity

1. **Migrations ANTES do swap, em UM único server** — o banco é
   multimaster (eveo/apoint/castrum replicam): `systemctl start
   sufficit-identity-migrator` uma vez em qualquer nó e a replicação
   propaga. O migrator é manual por design (unit estática, sem
   `[Install]`); o advisory lock `GET_LOCK` protege contra duas nodes
   rodando simultaneamente. Migrations com `MODIFY COLUMN` (rebuild de
   índices, como o 084) ainda pedem janela em tabelas grandes.
2. **Um servidor por vez** — o Identity é a espinha dorsal de SSO;
   nunca trocar os três simultaneamente.
3. **Segredos ficam fora do swap** — `SUFFICIT_SECRET_*` vêm de
   `/etc/sufficit/identity/vault-secrets.env`; certificados e
   `appsettings.{machine}.json` são carregados do live para o staging
   (exclusões do `config.json`).
4. **Health** — socket unix `/run/sufficit-identity/identity.sock`
   (`/health` liveness, `/health/ready` com banco) e discovery externo em
   `https://<server>.sufficit.com.br:26501/.well-known/openid-configuration`.
5. **Do seu PC, NUNCA use `-p:SufficitUseLocalSui=false`** — o irmão local
   é detectado automaticamente e fornece os componentes SUI mais recentes.
   A flag só é necessária para regenerar `packages.lock.json` antes de
   commitar (a CI valida em modo pacote, sem o irmão).
