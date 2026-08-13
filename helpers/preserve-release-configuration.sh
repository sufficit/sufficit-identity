#!/usr/bin/env bash

set -euo pipefail

usage() {
    echo "usage: preserve-release-configuration.sh <active-release> <candidate-release> [machine-name]" >&2
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
    usage
    exit 2
fi

releases_root=$(readlink -m -- "${IDENTITY_RELEASES_ROOT:-/opt/sufficit-identity.releases}")
active=$(readlink -f -- "$1" 2>/dev/null || true)
candidate=$(readlink -f -- "$2" 2>/dev/null || true)
machine_name=${3:-$(hostname -s)}
machine_name=$(printf '%s' "${machine_name}" | tr '[:upper:]' '[:lower:]')

if [[ -z ${active} || ! -d ${active} || -z ${candidate} || ! -d ${candidate} ]]; then
    echo "[prepare] Active and candidate releases must exist." >&2
    exit 1
fi
if [[ ${active} == "${candidate}" || ${releases_root} == / || \
    ${machine_name} == *[!A-Za-z0-9._-]* ]]; then
    echo "[prepare] Invalid release paths or machine name." >&2
    exit 2
fi
for release in "${active}" "${candidate}"; do
    case "${release}/" in
        "${releases_root}/"*) ;;
        *)
            echo "[prepare] Release is outside ${releases_root}: ${release}" >&2
            exit 2
            ;;
    esac
done

if find "${active}" -maxdepth 1 -type l -name 'appsettings*.json' \
    -print -quit | grep -q .
then
    echo "[prepare] Active configuration must not contain symbolic links." >&2
    exit 1
fi

mapfile -d '' configuration_files < <(
    find "${active}" -maxdepth 1 -type f -name 'appsettings*.json' \
        -print0 | sort -z
)
if ((${#configuration_files[@]} == 0)); then
    echo "[prepare] Active release has no appsettings configuration." >&2
    exit 1
fi

for required in \
    "${active}/appsettings.Production.json" \
    "${active}/appsettings.${machine_name}.json"
do
    if [[ ! -s ${required} ]]; then
        echo "[prepare] Required active configuration is missing: $(basename -- "${required}")" >&2
        exit 1
    fi
done

configuration_stage=$(mktemp -d "${candidate}/.configuration.XXXXXX")
cleanup() {
    rm -rf -- "${configuration_stage}"
}
trap cleanup EXIT INT TERM

for source in "${configuration_files[@]}"; do
    install -m 0640 -- "${source}" "${configuration_stage}/$(basename -- "${source}")"
done

# Candidate releases are not active yet, so replacing their top-level runtime
# configuration is safe. Remove every packaged/stale file to preserve the exact
# active set, including deletion of obsolete machine overlays.
find "${candidate}" -maxdepth 1 \
    \( -type f -o -type l \) -name 'appsettings*.json' -delete

for source in "${configuration_stage}"/appsettings*.json; do
    destination="${candidate}/$(basename -- "${source}")"
    if [[ ${EUID} -eq 0 ]]; then
        install -o root -g "${IDENTITY_RUNTIME_GROUP:-www-data}" -m 0640 \
            -- "${source}" "${destination}"
    else
        install -m 0640 -- "${source}" "${destination}"
    fi
done

configuration_manifest() {
    local root=$1 file
    while IFS= read -r -d '' file; do
        printf '%s  %s\n' \
            "$(sha256sum "${file}" | awk '{print $1}')" \
            "$(basename -- "${file}")"
    done < <(find "${root}" -maxdepth 1 -type f \
        -name 'appsettings*.json' -print0 | sort -z)
}

active_manifest=$(configuration_manifest "${active}")
candidate_manifest=$(configuration_manifest "${candidate}")
if [[ -z ${candidate_manifest} || ${candidate_manifest} != "${active_manifest}" ]]; then
    echo "[prepare] Candidate configuration does not match the active release." >&2
    exit 1
fi

printf '[prepare] Preserved %d configuration file(s) from %s.\n' \
    "${#configuration_files[@]}" "$(basename -- "${active}")"
