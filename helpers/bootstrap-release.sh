#!/usr/bin/env bash

# Privileged deployment/bootstrap boundary. Install this script root-owned
# under /usr/libexec/sufficit-identity; never execute the copy inside a mutable
# release with elevated systemd privileges.

set -euo pipefail

readonly app_name="sufficit-identity"
readonly app_link="/opt/${app_name}"
readonly releases_root="/opt/${app_name}.releases"
readonly config_dir="/etc/sufficit/identity"
readonly certificate_store="${config_dir}/certificate.pfx"
readonly environment="${ASPNETCORE_ENVIRONMENT:-Production}"

if [[ ${EUID} -ne 0 ]]; then
    echo "[bootstrap] ERROR: release bootstrap must run as root" >&2
    exit 1
fi

candidate=${1:-${app_link}}
release=$(readlink -f -- "${candidate}")
if [[ -z ${release} || ! -d ${release} ]]; then
    echo "[bootstrap] ERROR: release is missing: ${candidate}" >&2
    exit 1
fi

# An existing installation may initially be a real /opt/sufficit-identity
# directory. Atomic releases must live below the dedicated releases root.
if [[ ${candidate} != "${app_link}" ]]; then
    case "${release}/" in
        "${releases_root}/"*) ;;
        *)
            echo "[bootstrap] ERROR: release must be below ${releases_root}" >&2
            exit 2
            ;;
    esac
fi

install -d -o root -g www-data -m 0750 "${config_dir}"
certificate_destination="${release}/certificate.pfx"

if [[ -s ${certificate_store} ]]; then
    install -o root -g www-data -m 0640 \
        "${certificate_store}" "${certificate_destination}"
    echo "[bootstrap] Persistent application certificate installed"
elif [[ -s ${certificate_destination} ]]; then
    install -o root -g www-data -m 0640 \
        "${certificate_destination}" "${certificate_store}"
    echo "[bootstrap] Application certificate persisted outside the release"
elif [[ ${environment} == "Development" ]]; then
    temporary_directory=$(mktemp -d)
    trap 'rm -rf -- "${temporary_directory}"' EXIT
    password_file="${config_dir}/certificate.password"
    umask 0077
    openssl rand -base64 48 > "${password_file}"
    chown root:www-data "${password_file}"
    chmod 0640 "${password_file}"
    openssl req -x509 -newkey rsa:3072 \
        -keyout "${temporary_directory}/key.pem" \
        -out "${temporary_directory}/certificate.pem" \
        -days 365 -nodes -subj '/CN=identity.local' >/dev/null 2>&1
    openssl pkcs12 -export \
        -in "${temporary_directory}/certificate.pem" \
        -inkey "${temporary_directory}/key.pem" \
        -out "${certificate_store}" \
        -passout "file:${password_file}" >/dev/null 2>&1
    echo "[bootstrap] Development certificate generated with a random protected password"
else
    echo "[bootstrap] ERROR: ${certificate_store} is required in ${environment}" >&2
    exit 1
fi

# Application binaries/configuration are immutable to dotnetuser. Only the
# certificate is group-readable; writable runtime state is explicitly created
# by systemd or lives in external databases/caches.
chown -R root:root "${release}"
chmod -R go-w "${release}"
install -o root -g www-data -m 0640 \
    "${certificate_store}" "${certificate_destination}"

echo "[bootstrap] Release ownership and certificate state prepared"
