#!/usr/bin/env bash
# Compares a deployment's schema snapshot with a fresh install from
# sql/001-create-empty-database.sql (plan F8). Needs Docker. Usage:
#   check-schema-parity.sh <snapshot.txt> [mariadb-image]
# where snapshot.txt is the output of schema-snapshot.sql on the deployment.
# Exit 0 when only the history's ProductVersion differs.
set -euo pipefail
snapshot=${1:?snapshot file}
image=${2:-mariadb:10.4.34}
here=$(cd "$(dirname "$0")" && pwd)
name=identity-schema-parity-$$
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$name" -e MARIADB_ROOT_PASSWORD=parity -e MARIADB_DATABASE=identity "$image" \
  --sql-mode="STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION" \
  --character-set-server=utf8mb4 --collation-server=utf8mb4_general_ci >/dev/null
sql() { docker exec -i "$name" mysql -uroot -pparity -N -B --raw identity; }
for _ in $(seq 1 60); do sql <<<"SELECT 1" >/dev/null 2>&1 && break; sleep 2; done
sql < "$here/sql/001-create-empty-database.sql" >/dev/null
fresh=$(mktemp); sql < "$here/schema-snapshot.sql" > "$fresh"
# Leftover *_bkp_* tables are reported separately; ProductVersion is history, not schema.
normalize() { grep -v '_bkp_' "$1" | awk -F'\t' 'BEGIN{OFS="\t"} $1=="M"{$3=""} {print}' | sort; }
if diff <(normalize "$snapshot") <(normalize "$fresh"); then
  echo "Schema matches a fresh install."
else
  echo "Schema differs from a fresh install (< deployment, > fresh)." >&2; exit 1
fi
leftovers=$(grep -c '^T	.*_bkp_' "$snapshot" || true)
[ "$leftovers" -gt 0 ] && echo "Note: $leftovers backup table(s) left in the deployment." || true
