#!/usr/bin/env bash

set -euo pipefail

readonly app_name="sufficit-identity"
readonly app_link="/opt/${app_name}"
readonly releases_root="/opt/${app_name}.releases"
readonly lock_file="/run/lock/${app_name}-deploy.lock"
readonly health_url="https://identity.sufficit.com.br:26501/health"
readonly health_timeout_seconds=45

usage() {
    echo "usage: $0 --current | ${releases_root}/<release>" >&2
}

wait_for_health() {
    local deadline=$((SECONDS + health_timeout_seconds))

    until curl --fail --silent --show-error --max-time 5 \
        --output /dev/null \
        --resolve identity.sufficit.com.br:26501:127.0.0.1 \
        "${health_url}"
    do
        if (( SECONDS >= deadline )); then
            return 1
        fi
        sleep 1
    done
}

if [[ $# -ne 1 ]]; then
    usage
    exit 2
fi

exec 9>"${lock_file}"
if ! flock --nonblock 9; then
    echo "[deploy] Another Identity activation/restart is already running" >&2
    exit 75
fi

previous_release=$(readlink -f "${app_link}")
if [[ -z "${previous_release}" || ! -d "${previous_release}" ]]; then
    echo "[deploy] Active release symlink is missing or invalid: ${app_link}" >&2
    exit 1
fi

switch_release=true
if [[ $1 == "--current" ]]; then
    candidate_release=${previous_release}
    switch_release=false
else
    candidate_release=$(readlink -f -- "$1")
fi

case "${candidate_release}/" in
    "${releases_root}/"*) ;;
    *)
        echo "[deploy] Release must be below ${releases_root}: ${candidate_release}" >&2
        exit 2
        ;;
esac

for required in \
    Sufficit.Identity.Server.dll \
    appsettings.Production.json \
    appsettings.eveo-apps.json \
    helpers/bootstrap-release.sh \
    helpers/prestart.sh
do
    if [[ ! -f "${candidate_release}/${required}" ]]; then
        echo "[deploy] Required release file is missing: ${required}" >&2
        exit 1
    fi
done

# Prepare certificate state and immutable ownership before the symlink switch.
# This calls the root-owned installed helper, never code from the candidate.
/usr/libexec/${app_name}/bootstrap-release.sh "${candidate_release}"

next_link="${app_link}.next.$$"
cleanup() {
    rm -f -- "${next_link}"
}
trap cleanup EXIT

activate_symlink() {
    local target=$1
    ln -s -- "${target}" "${next_link}"
    mv -Tf -- "${next_link}" "${app_link}"
}

if [[ ${switch_release} == true && ${candidate_release} != "${previous_release}" ]]; then
    activate_symlink "${candidate_release}"
    echo "[deploy] Activated release ${candidate_release}"
fi

if systemctl restart "${app_name}.service" && wait_for_health; then
    echo "[deploy] Identity is healthy on ${candidate_release}"
    exit 0
fi

echo "[deploy] Identity failed its health gate on ${candidate_release}" >&2
if [[ ${switch_release} == true && ${candidate_release} != "${previous_release}" ]]; then
    echo "[deploy] Rolling back to ${previous_release}" >&2
    activate_symlink "${previous_release}"
    systemctl restart "${app_name}.service"
    if wait_for_health; then
        echo "[deploy] Rollback is healthy on ${previous_release}" >&2
    else
        echo "[deploy] CRITICAL: rollback also failed its health gate" >&2
    fi
fi

exit 1
