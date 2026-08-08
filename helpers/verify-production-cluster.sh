#!/usr/bin/env bash

set -euo pipefail

readonly app_name="sufficit-identity"
readonly app_link="/opt/${app_name}"
readonly releases_root="/opt/${app_name}.releases"
readonly health_host="identity.sufficit.com.br"
readonly health_port="26501"
readonly health_url="https://${health_host}:${health_port}"
readonly jwks_path="/.well-known/openid-configuration/jwks"

usage() {
    cat >&2 <<'EOF'
usage: verify-production-cluster.sh <expected-revision> [host ...]

The default hosts come from IDENTITY_PRODUCTION_HOSTS (comma-separated), or
the three production Identity nodes when that variable is not set.

SSH connection settings:
  IDENTITY_SSH_USER (default: root)
  IDENTITY_SSH_PORT (default: 26492)
  IDENTITY_SSH_KEY  (optional private key)
  IDENTITY_SSH_STRICT_HOST_KEY_CHECKING (default: yes)

Optional SHA-256 pins:
  IDENTITY_EXPECTED_CERT_SHA256
  IDENTITY_EXPECTED_JWKS_SHA256
EOF
}

if [[ $# -lt 1 || -z ${1:-} ]]; then
    usage
    exit 2
fi

expected_revision=$1
shift

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

failures=0
baseline_cert_sha=${IDENTITY_EXPECTED_CERT_SHA256:-}
baseline_jwks_sha=${IDENTITY_EXPECTED_JWKS_SHA256:-}

for host in "${hosts[@]}"; do
    [[ -n ${host} ]] || continue
    target="${IDENTITY_SSH_USER:-root}@${host}"
    result=''

    if ! result=$(ssh "${ssh_options[@]}" "${target}" bash -s -- "${expected_revision}" <<'REMOTE_CHECK'
set -u

expected=$1
app_link=/opt/sufficit-identity
active=$(readlink -f -- "${app_link}" 2>/dev/null || true)
revision=missing
revision_source=missing
if [[ -n ${active} && -f ${active}/REVISION ]]; then
    revision=$(tr -d '[:space:]' < "${active}/REVISION")
    revision_source=REVISION
elif [[ -n ${active} ]]; then
    revision=$(basename -- "${active}")
    revision_source=release-name
fi

service=$(systemctl is-active sufficit-identity.service 2>/dev/null || true)
[[ -n ${service} ]] || service=unknown

health=Unhealthy
if curl --fail --silent --show-error --max-time 10 \
    --resolve identity.sufficit.com.br:26501:127.0.0.1 \
    "https://identity.sufficit.com.br:26501/health" >/dev/null 2>&1; then
    health=Healthy
fi

ready=Unhealthy
if curl --fail --silent --show-error --max-time 10 \
    --resolve identity.sufficit.com.br:26501:127.0.0.1 \
    "https://identity.sufficit.com.br:26501/health/ready" >/dev/null 2>&1; then
    ready=Healthy
fi

cert_sha=missing
if [[ -f /etc/sufficit/identity/certificate.pfx ]]; then
    cert_sha=$(sha256sum /etc/sufficit/identity/certificate.pfx | awk '{print $1}')
fi

jwks_sha=missing
if jwks_sha=$(curl --fail --silent --show-error --max-time 10 \
    --resolve identity.sufficit.com.br:26501:127.0.0.1 \
    "https://identity.sufficit.com.br:26501/.well-known/openid-configuration/jwks" \
    | sha256sum | awk '{print $1}'); then
    :
else
    jwks_sha=missing
fi

printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${revision}" "${revision_source}" "${service}" "${health}" \
    "${ready}" "${cert_sha}" "${jwks_sha}"

revision_ok=false
if [[ ${revision} == "${expected}" || ${active} == *"${expected}"* ]]; then
    revision_ok=true
fi
[[ ${revision_ok} == true && ${service} == active && ${health} == Healthy && \
    ${ready} == Healthy && ${cert_sha} != missing && ${jwks_sha} != missing ]]
REMOTE_CHECK
    ); then
        echo "[cluster] ${host}: SSH/health check failed" >&2
        failures=$((failures + 1))
        continue
    fi

    IFS=$'\t' read -r revision revision_source service health ready cert_sha jwks_sha <<< "${result}"
    printf '[cluster] %-34s revision=%s (%s) service=%s health=%s ready=%s cert=%s jwks=%s\n' \
        "${host}" "${revision}" "${revision_source}" "${service}" "${health}" \
        "${ready}" "${cert_sha}" "${jwks_sha}"

    if [[ ${revision} != "${expected_revision}" && ${revision} != *"${expected_revision}"* ]]; then
        # A legacy release may not have REVISION yet; its release directory must
        # still carry the expected revision in its name (checked remotely).
        echo "[cluster] ${host}: expected revision ${expected_revision}, got ${revision}" >&2
        failures=$((failures + 1))
    fi
    if [[ ${service} != active || ${health} != Healthy || ${ready} != Healthy ]]; then
        echo "[cluster] ${host}: service/readiness gate failed" >&2
        failures=$((failures + 1))
    fi
    if [[ ${cert_sha} == missing || ${jwks_sha} == missing ]]; then
        echo "[cluster] ${host}: certificate or JWKS digest is unavailable" >&2
        failures=$((failures + 1))
    fi

    if [[ -z ${baseline_cert_sha} ]]; then
        baseline_cert_sha=${cert_sha}
    elif [[ ${cert_sha} != "${baseline_cert_sha}" ]]; then
        echo "[cluster] ${host}: certificate SHA differs from cluster baseline" >&2
        failures=$((failures + 1))
    fi
    if [[ -z ${baseline_jwks_sha} ]]; then
        baseline_jwks_sha=${jwks_sha}
    elif [[ ${jwks_sha} != "${baseline_jwks_sha}" ]]; then
        echo "[cluster] ${host}: JWKS SHA differs from cluster baseline" >&2
        failures=$((failures + 1))
    fi
done

if ((failures > 0)); then
    echo "[cluster] Production cluster verification failed (${failures} gate failures)." >&2
    exit 1
fi

echo "[cluster] Production cluster is uniform at revision ${expected_revision}."
