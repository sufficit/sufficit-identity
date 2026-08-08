#!/usr/bin/env bash

# Runtime preflight. This file is installed root-owned under
# /usr/libexec/sufficit-identity and runs as the unprivileged service account.
# All privileged release/certificate preparation belongs to
# bootstrap-release.sh and is performed by the deployment boundary.

set -euo pipefail

readonly app_name="sufficit-identity"
if (( $# > 2 )); then
    echo "[prestart] usage: prestart.sh [app-link] [config-dir]" >&2
    exit 2
fi
readonly app_link="${1:-/opt/${app_name}}"
readonly config_dir="${2:-/etc/sufficit/identity}"
readonly certificate="${app_link}/certificate.pfx"
readonly environment="${ASPNETCORE_ENVIRONMENT:-Production}"

release=$(readlink -f -- "${app_link}")
if [[ -z ${release} || ! -d ${release} ]]; then
    echo "[prestart] ERROR: active release is missing: ${app_link}" >&2
    exit 1
fi

if [[ ! -r ${certificate} || ! -s ${certificate} ]]; then
    echo "[prestart] ERROR: readable, non-empty application certificate is required in ${environment}" >&2
    exit 1
fi

# Neither the service user nor its group may modify release contents. The PFX
# is root-owned and group-readable; runtime state belongs in systemd's /run
# directory or external stores, never beside application binaries.
unsafe_path=$(find "${release}" -xdev \( -perm -0020 -o -perm -0002 \) -print -quit)
if [[ -n ${unsafe_path} ]]; then
    echo "[prestart] ERROR: release contains a group/other-writable path: ${unsafe_path}" >&2
    exit 1
fi

certificate_owner=$(stat -c '%U:%G' -- "${certificate}")
certificate_mode=$(stat -c '%a' -- "${certificate}")
if [[ ${certificate_owner} != "root:www-data" ]]; then
    echo "[prestart] ERROR: certificate owner must be root:www-data (found ${certificate_owner})" >&2
    exit 1
fi
if (( (8#${certificate_mode} & 8#022) != 0 )); then
    echo "[prestart] ERROR: certificate must not be writable by group/other" >&2
    exit 1
fi

# When an operator supplies a password through the environment or a protected
# password file, validate that the PFX is readable and contains a private key.
# The application performs the same validation while loading configured
# signing/encryption credentials, so invalid material still prevents startup
# when legacy deployments keep the password only in application configuration.
password_file=${SUFFICIT_IDENTITY_CERTIFICATE_PASSWORD_FILE:-${config_dir}/certificate.password}
temporary_directory=
cleanup() {
    if [[ -n ${temporary_directory} ]]; then
        rm -rf -- "${temporary_directory}"
    fi
}
trap cleanup EXIT

if [[ -n ${SUFFICIT_IDENTITY_CERTIFICATE_PASSWORD:-} || -r ${password_file} ]]; then
    temporary_directory=$(mktemp -d)
    password_argument="env:SUFFICIT_IDENTITY_CERTIFICATE_PASSWORD"
    if [[ -z ${SUFFICIT_IDENTITY_CERTIFICATE_PASSWORD:-} ]]; then
        password_argument="file:${password_file}"
    fi
    openssl pkcs12 -in "${certificate}" -nocerts -nodes \
        -passin "${password_argument}" \
        -out "${temporary_directory}/private-key.pem" >/dev/null 2>&1
    openssl pkey -in "${temporary_directory}/private-key.pem" \
        -check -noout >/dev/null 2>&1
fi

echo "[prestart] Runtime invariants verified"
