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

dotnet_bin=""
for candidate in \
    /opt/dotnet-10/dotnet \
    "${DOTNET_ROOT:-}/dotnet" \
    /usr/share/dotnet/dotnet; do
    if [[ -n ${candidate} && -x ${candidate} ]]; then
        dotnet_bin="${candidate}"
        break
    fi
done

if [[ -z ${dotnet_bin} ]]; then
    echo "[migrator] ERROR: no supported .NET runtime executable was found" >&2
    exit 127
fi

exec "${dotnet_bin}" \
    Sufficit.Identity.Server.dll --migrate-only
