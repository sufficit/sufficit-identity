#!/usr/bin/env bash

set -euo pipefail

readonly app_link="/opt/sufficit-identity"
readonly preflight="/usr/libexec/sufficit-identity/prestart.sh"

if [[ ! -x ${preflight} ]]; then
    echo "[migrator] ERROR: installed runtime preflight is missing" >&2
    exit 1
fi

"${preflight}"
cd "${app_link}"
exec /usr/share/dotnet/dotnet \
    Sufficit.Identity.Server.dll --migrate-only
