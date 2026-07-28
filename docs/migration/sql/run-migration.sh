#!/bin/bash
set -euo pipefail

####################################
##  SUFFICIT IDENTITY — MIGRACAO
##  Migra dados do banco legado (Duende `identity`) para o novo (OpenIddict `identity2`).
##  Idempotente: recria o banco destino do zero a cada execucao.
##
##  Uso: ./run-migration.sh [host] [port] [user] [password]
##  Padrao: castrum-proxy-local.sufficit.com.br 26493 identity '<password>'
####################################

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST="${1:-castrum-proxy-local.sufficit.com.br}"
PORT="${2:-26493}"
USER="${3:-identity}"
PASS="${4:-flgxLDZfTtEAWGZ5+V\$t3uaK*Xk-ICEQUd-*}"
SOURCE_DB="identity"
TARGET_DB="identity2"

MYSQL="mysql -h ${HOST} -P ${PORT} -u ${USER} -p'${PASS}'"

echo "========================================"
echo "  Sufficit Identity — Migracao Duende → OpenIddict"
echo "  Host: ${HOST}:${PORT}"
echo "  Source: ${SOURCE_DB} → Target: ${TARGET_DB}"
echo "========================================"
echo ""

# 1. Drop + Create target database
echo "[1/5] Recriando banco ${TARGET_DB}..."
mysql -h "${HOST}" -P "${PORT}" -u "${USER}" -p"${PASS}" -e \
    "DROP DATABASE IF EXISTS ${TARGET_DB}; CREATE DATABASE ${TARGET_DB} CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;"
echo "  OK — ${TARGET_DB} recriado"
echo ""

# 2. Apply canonical schema
echo "[2/5] Aplicando schema OpenIddict (001-create-empty-database.sql)..."
mysql -h "${HOST}" -P "${PORT}" -u "${USER}" -p"${PASS}" "${TARGET_DB}" < "${SCRIPT_DIR}/001-create-empty-database.sql"
echo "  OK — schema aplicado"
echo ""

# 3. Migrate Identity data
echo "[3/5] Migrando dados Identity (users, roles, claims, logins, tokens)..."
mysql -h "${HOST}" -P "${PORT}" -u "${USER}" -p"${PASS}" "${TARGET_DB}" < "${SCRIPT_DIR}/020-migrate-identity-data.sql"
echo "  OK — dados Identity migrados"
echo ""

# 4. Migrate OpenIddict clients + scopes
echo "[4/5] Migrando clients + scopes (Duende → OpenIddict)..."
mysql -h "${HOST}" -P "${PORT}" -u "${USER}" -p"${PASS}" "${TARGET_DB}" < "${SCRIPT_DIR}/030-migrate-openiddict-clients.sql"
echo "  OK — clients e scopes migrados"
echo ""

# 5. Verify
echo "[5/5] Verificando migracao..."
mysql -h "${HOST}" -P "${PORT}" -u "${USER}" -p"${PASS}" "${TARGET_DB}" < "${SCRIPT_DIR}/040-migrate-verify.sql"
echo ""
echo "========================================"
echo "  Migracao concluida. Verifique os counts acima."
echo "  Se algum 'diff' for diferente de 0, investigar."
echo "========================================"
