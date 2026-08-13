#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: prepare-cluster-release.sh <archive> <release-name> <expected-revision> [host ...]

Uploads one configuration-free archive to every production node, extracts it
atomically below /opt/sufficit-identity.releases and copies the exact active
appsettings set from that node into the candidate. No configuration values are
printed or transported through the operator workstation.
EOF
}

if [[ $# -lt 3 ]]; then
    usage
    exit 2
fi

archive=$1
release_name=$2
expected_revision=$3
shift 3

if [[ ! -s ${archive} ]]; then
    echo "[prepare] Release archive is missing: ${archive}" >&2
    exit 1
fi
if [[ -z ${release_name} || -z ${expected_revision} || ${release_name} == */* || \
    ${release_name} == .* || ${release_name} == *[!A-Za-z0-9._-]* ]]; then
    echo "[prepare] Release name and revision must be non-empty safe identifiers." >&2
    exit 2
fi

if (($# > 0)); then
    hosts=("$@")
else
    host_list=${IDENTITY_PRODUCTION_HOSTS:-eveo-apps.sufficit.com.br,apoint-apps.sufficit.com.br,castrum-apps.sufficit.com.br}
    IFS=',' read -r -a hosts <<< "${host_list}"
fi
if ((${#hosts[@]} == 0)); then
    echo "[prepare] No production hosts configured." >&2
    exit 2
fi

script_directory=$(cd -- "$(dirname -- "$0")" && pwd)
preserve_helper="${script_directory}/preserve-release-configuration.sh"
if [[ ! -s ${preserve_helper} ]]; then
    echo "[prepare] Configuration preservation helper is missing." >&2
    exit 1
fi

archive_sha256=$(sha256sum "${archive}" | awk '{print $1}')
helper_sha256=$(sha256sum "${preserve_helper}" | awk '{print $1}')
ssh_common=(
    -o BatchMode=yes
    -o ConnectTimeout="${IDENTITY_SSH_CONNECT_TIMEOUT:-10}"
    -o StrictHostKeyChecking="${IDENTITY_SSH_STRICT_HOST_KEY_CHECKING:-yes}"
)
if [[ -n ${IDENTITY_SSH_KEY:-} ]]; then
    ssh_common+=(-i "${IDENTITY_SSH_KEY}" -o IdentitiesOnly=yes)
fi
ssh_options=("${ssh_common[@]}" -p "${IDENTITY_SSH_PORT:-26492}")
scp_options=("${ssh_common[@]}" -P "${IDENTITY_SSH_PORT:-26492}")

for host in "${hosts[@]}"; do
    [[ -n ${host} ]] || continue
    target="${IDENTITY_SSH_USER:-root}@${host}"
    remote_archive="/tmp/sufficit-identity-${release_name}.tar.gz"
    remote_helper="/tmp/sufficit-identity-${release_name}.preserve.sh"

    echo "[prepare] Uploading ${release_name} to ${host}..."
    scp "${scp_options[@]}" -- \
        "${archive}" "${target}:${remote_archive}"
    scp "${scp_options[@]}" -- \
        "${preserve_helper}" "${target}:${remote_helper}"

    ssh "${ssh_options[@]}" "${target}" bash -s -- \
        "${release_name}" "${expected_revision}" \
        "${archive_sha256}" "${helper_sha256}" \
        "${remote_archive}" "${remote_helper}" <<'REMOTE_PREPARE'
set -euo pipefail

release_name=$1
expected_revision=$2
expected_archive_sha=$3
expected_helper_sha=$4
archive=$5
preserve_helper=$6
releases_root=/opt/sufficit-identity.releases
candidate=${releases_root}/${release_name}
preparing=${releases_root}/.${release_name}.preparing.$$

cleanup() {
    rm -f -- "${archive}" "${preserve_helper}"
    rm -rf -- "${preparing}"
}
trap cleanup EXIT INT TERM

printf '%s  %s\n' "${expected_archive_sha}" "${archive}" | sha256sum -c -
printf '%s  %s\n' "${expected_helper_sha}" "${preserve_helper}" | sha256sum -c -
if [[ -e ${candidate} ]]; then
    echo "[prepare] Candidate already exists: ${candidate}" >&2
    exit 1
fi

active=$(readlink -f -- /opt/sufficit-identity 2>/dev/null || true)
case "${active}/" in
    "${releases_root}/"*) ;;
    *)
        echo "[prepare] Active release is missing or outside ${releases_root}." >&2
        exit 1
        ;;
esac

if tar -tzf "${archive}" | awk '
    /^\// || /(^|\/)\.\.($|\/)/ { invalid=1 }
    END { exit invalid ? 0 : 1 }
'; then
    echo "[prepare] Archive contains an unsafe path." >&2
    exit 1
fi

install -d -o root -g root -m 0755 "${preparing}"
tar -xzf "${archive}" -C "${preparing}"
if find "${preparing}" -type l -print -quit | grep -q .; then
    echo "[prepare] Archive must not contain symbolic links." >&2
    exit 1
fi
if find "${preparing}" -maxdepth 1 -type f \
    \( -name 'appsettings*.json' -o -name 'certificate*.pfx' \) \
    -print -quit | grep -q .
then
    echo "[prepare] Archive contains forbidden runtime configuration or certificates." >&2
    exit 1
fi

for required in \
    Sufficit.Identity.Server.dll \
    helpers/activate-release.sh \
    helpers/bootstrap-release.sh \
    helpers/package-release.sh \
    helpers/prepare-cluster-release.sh \
    helpers/preserve-release-configuration.sh \
    helpers/prestart.sh \
    REVISION
do
    if [[ ! -s ${preparing}/${required} ]]; then
        echo "[prepare] Required release file is missing: ${required}" >&2
        exit 1
    fi
done
revision=$(tr -d '[:space:]' < "${preparing}/REVISION")
if [[ ${revision} != "${expected_revision}" ]]; then
    echo "[prepare] Candidate revision mismatch." >&2
    exit 1
fi

chmod 0500 "${preserve_helper}"
IDENTITY_RELEASES_ROOT="${releases_root}" \
    "${preserve_helper}" "${active}" "${preparing}" "$(hostname -s)"
mv -- "${preparing}" "${candidate}"
printf '[prepare] %s ready at revision %s; configuration inherited from %s.\n' \
    "$(hostname -f)" "${revision}" "$(basename -- "${active}")"
REMOTE_PREPARE
done

echo "[prepare] Release ${release_name} is ready on every configured node."
