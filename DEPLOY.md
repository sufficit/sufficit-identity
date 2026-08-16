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
# Publicar localmente em MODO PACOTE (production parity — nunca publique
# contra o checkout irmão do SUI):
dotnet publish src/server/Sufficit.Identity.Server.csproj \
    -c Release -p:SufficitUseLocalSui=false \
    -o publish-net10.0

# Aplicar migrations pendentes NO BANCO DAQUELE SERVER (antes do swap!):
#    helpers/migrate-database.sh <server>   (ver cabeçalho do script)

# Deploy staged (upload → stop → swap atômico → start → health):
python3 deploy.py eveo-apps
python3 deploy.py apoint-apps
python3 deploy.py castrum-apps
```

## 🔒 Regras específicas do Identity

1. **Migrations ANTES do swap** — o binário novo assume o schema novo;
   o binário velho ignora adições. O script `084` (collation binária) é
   idempotente, por tabela e retomável, mas faz `MODIFY COLUMN` (rebuild
   de índices): em `tokens` grande, janela de manutenção.
2. **Um servidor por vez** — o Identity é a espinha dorsal de SSO;
   nunca trocar os três simultaneamente.
3. **Segredos ficam fora do swap** — `SUFFICIT_SECRET_*` vêm de
   `/etc/sufficit/identity/vault-secrets.env`; certificados e
   `appsettings.{machine}.json` são carregados do live para o staging
   (exclusões do `config.json`).
4. **Health** — socket unix `/run/sufficit-identity/identity.sock`
   (`/health` liveness, `/health/ready` com banco) e discovery externo em
   `https://<server>.sufficit.com.br:26501/.well-known/openid-configuration`.
5. **Publicar sempre com `-p:SufficitUseLocalSui=false`** — publica a
   mesma graph de pacotes que a CI audita (locks em modo pacote).
