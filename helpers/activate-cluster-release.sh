#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: activate-cluster-release.sh <release-name> <expected-revision> [host ...]

The release must already be prepared under /opt/sufficit-identity.releases on
every host by prepare-cluster-release.sh. The script acquires a cluster-wide
lease on the first host, then activates hosts one at a time through
activate-release.sh. If a later host fails, hosts already changed by this
invocation are rolled back to their previous release.

The default hosts come from IDENTITY_PRODUCTION_HOSTS (comma-separated), or
eveo-apps, apoint-apps and castrum-apps when the variable is not set. Set
IDENTITY_COORDINATOR_HOST to override the first host used for the lease.

SSH connection settings are the same as verify-production-cluster.sh:
  IDENTITY_SSH_USER, IDENTITY_SSH_PORT, IDENTITY_SSH_KEY,
  IDENTITY_SSH_STRICT_HOST_KEY_CHECKING.
EOF
}

if [[ $# -lt 2 ]]; then
    usage
    exit 2
fi

release_name=$1
expected_revision=$2
shift 2

if [[ -z ${release_name} || -z ${expected_revision} || ${release_name} == */* || \
    ${release_name} == .* || ${release_name} == *[!A-Za-z0-9._-]* ]]; then
    echo "[cluster] release-name and expected-revision must be non-empty safe identifiers." >&2
    exit 2
fi

if (($# > 0)); then
    hosts=("$@")
else
    host_list=${IDENTITY_PRODUCTION_HOSTS:-eveo-apps.sufficit.com.br,apoint-apps.sufficit.com.br,castrum-apps.sufficit.com.br}
    IFS=',' read -r -a hosts <<< "${host_list}"
fi

if ((${#hosts[@]} == 0)); then
    echo "[cluster] No production hosts configured." >&2
    exit 2
fi

ssh_options=(
    -o BatchMode=yes
    -o ConnectTimeout="${IDENTITY_SSH_CONNECT_TIMEOUT:-10}"
    -o StrictHostKeyChecking="${IDENTITY_SSH_STRICT_HOST_KEY_CHECKING:-yes}"
    -p "${IDENTITY_SSH_PORT:-26492}"
)
if [[ -n ${IDENTITY_SSH_KEY:-} ]]; then
    ssh_options+=(-i "${IDENTITY_SSH_KEY}")
fi

lock_root=${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}
mkdir -p -- "${lock_root}"
exec 9>"${lock_root}/sufficit-identity-cluster-deploy.lock"
if ! flock --nonblock 9; then
    echo "[cluster] Another local cluster deployment is already running." >&2
    exit 75
fi

coordinator=${IDENTITY_COORDINATOR_HOST:-${hosts[0]}}
coordinator_target="${IDENTITY_SSH_USER:-root}@${coordinator}"
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/sufficit-identity-cluster.XXXXXX")
control_fifo="${temporary_directory}/control"
status_file="${temporary_directory}/status"
error_file="${temporary_directory}/error"
mkfifo -- "${control_fifo}"
remote_lock_pid=''
lock_fd=''

cleanup() {
    if [[ -n ${lock_fd} ]]; then
        printf 'RELEASE\n' >&"${lock_fd}" 2>/dev/null || true
        exec {lock_fd}>&- 2>/dev/null || true
    fi
    if [[ -n ${remote_lock_pid} ]]; then
        kill "${remote_lock_pid}" 2>/dev/null || true
        wait "${remote_lock_pid}" 2>/dev/null || true
    fi
    rm -rf -- "${temporary_directory}"
}
trap cleanup EXIT INT TERM

echo "[cluster] Acquiring deployment lease on ${coordinator}..."
ssh "${ssh_options[@]}" "${coordinator_target}" \
    'set -u; exec 9>/run/lock/sufficit-identity-cluster-deploy.lock; if ! flock --nonblock 9; then printf "LOCK_BUSY\\n"; exit 75; fi; printf "LOCK_ACQUIRED\\n"; IFS= read -r command || true; [[ ${command:-} == RELEASE ]]' \
    <"${control_fifo}" >"${status_file}" 2>"${error_file}" &
remote_lock_pid=$!

exec {lock_fd}>"${control_fifo}"
lock_status=''
lock_deadline=$((SECONDS + ${IDENTITY_LOCK_TIMEOUT:-15}))
while [[ ! -s ${status_file} && SECONDS -lt ${lock_deadline} ]]; do
    if ! kill -0 "${remote_lock_pid}" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if [[ -s ${status_file} ]]; then
    IFS= read -r lock_status <"${status_file}" || true
fi
if [[ -z ${lock_status} ]]; then
    echo "[cluster] Timed out acquiring the production deployment lease." >&2
    sed 's/^/[cluster] /' "${error_file}" >&2 || true
    exit 75
fi
if [[ ${lock_status} != LOCK_ACQUIRED ]]; then
    echo "[cluster] Production deployment lease is busy on ${coordinator}." >&2
    sed 's/^/[cluster] /' "${error_file}" >&2 || true
    exit 75
fi

declare -A previous_release=()
changed_hosts=()

for host in "${hosts[@]}"; do
    [[ -n ${host} ]] || continue
    target="${IDENTITY_SSH_USER:-root}@${host}"
    preflight=''
    if ! preflight=$(ssh "${ssh_options[@]}" "${target}" bash -s -- "${release_name}" "${expected_revision}" <<'REMOTE_PREFLIGHT'
set -u
release_name=$1
expected=$2
candidate=/opt/sufficit-identity.releases/${release_name}
active=$(readlink -f -- /opt/sufficit-identity 2>/dev/null || true)
if [[ ! -d ${candidate} ]]; then
    printf 'candidate-missing\n' >&2
    exit 1
fi
if [[ -f ${candidate}/REVISION ]]; then
    revision=$(tr -d '[:space:]' < "${candidate}/REVISION")
else
    revision=$(basename -- "${candidate}")
fi
if [[ ${revision} != "${expected}" && ${candidate} != *"${expected}"* ]]; then
    printf 'candidate-revision-mismatch: expected=%s actual=%s\n' "${expected}" "${revision}" >&2
    exit 1
fi
if [[ -z ${active} || ! -d ${active} ]]; then
    printf 'active-release-missing\n' >&2
    exit 1
fi
case "${active}/" in
    /opt/sufficit-identity.releases/*/) ;;
    *)
        printf 'active-release-outside-release-root: %s\n' "${active}" >&2
        exit 1
        ;;
esac

configuration_manifest() {
    local root=$1 file
    while IFS= read -r -d '' file; do
        printf '%s  %s\n' \
            "$(sha256sum "${file}" | awk '{print $1}')" \
            "$(basename -- "${file}")"
    done < <(find "${root}" -maxdepth 1 -type f \
        -name 'appsettings*.json' -print0 | sort -z)
}

if find "${active}" "${candidate}" -maxdepth 1 -type l \
    -name 'appsettings*.json' -print -quit | grep -q .
then
    printf 'candidate-configuration-symlink-rejected\n' >&2
    exit 1
fi
active_configuration=$(configuration_manifest "${active}")
candidate_configuration=$(configuration_manifest "${candidate}")
if [[ -z ${active_configuration} || \
    ${candidate_configuration} != "${active_configuration}" ]]; then
    printf 'candidate-configuration-drift: run prepare-cluster-release.sh again\n' >&2
    exit 1
fi
printf '%s\n' "${active}"
REMOTE_PREFLIGHT
    ); then
        echo "[cluster] ${host}: candidate preflight failed." >&2
        sed 's/^/[cluster] /' <<<"${preflight}" >&2 || true
        exit 1
    fi
    previous_release["${host}"]=${preflight##*$'\n'}
    echo "[cluster] ${host}: candidate ready; previous=${previous_release[${host}]}"
done

rollback() {
    local rollback_host previous target
    echo "[cluster] Rolling back hosts changed by this invocation..." >&2
    for ((rollback_host=${#changed_hosts[@]} - 1; rollback_host >= 0; rollback_host--)); do
        target="${IDENTITY_SSH_USER:-root}@${changed_hosts[rollback_host]}"
        previous=${previous_release[${changed_hosts[rollback_host]}]}
        if ssh "${ssh_options[@]}" "${target}" \
            /opt/sufficit-identity/helpers/activate-release.sh "${previous}"; then
            echo "[cluster] ${changed_hosts[rollback_host]}: rollback healthy at ${previous}" >&2
        else
            echo "[cluster] CRITICAL: rollback failed on ${changed_hosts[rollback_host]}" >&2
        fi
    done
}

for host in "${hosts[@]}"; do
    [[ -n ${host} ]] || continue
    target="${IDENTITY_SSH_USER:-root}@${host}"
    echo "[cluster] Activating ${release_name} on ${host}..."
    if ! ssh "${ssh_options[@]}" "${target}" \
        /opt/sufficit-identity/helpers/activate-release.sh \
        "/opt/sufficit-identity.releases/${release_name}"; then
        echo "[cluster] ${host}: activation failed." >&2
        rollback
        exit 1
    fi
    changed_hosts+=("${host}")
done

echo "[cluster] Running the post-activation uniformity gate..."
if ! "$(dirname -- "$0")/verify-production-cluster.sh" "${expected_revision}" "${hosts[@]}"; then
    rollback
    exit 1
fi

echo "[cluster] Cluster activation completed at revision ${expected_revision}."
