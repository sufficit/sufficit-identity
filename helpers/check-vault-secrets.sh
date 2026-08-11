#!/usr/bin/env bash

set -euo pipefail

config_file=${1:-/etc/sufficit/identity/vault-secrets.env}

if [[ ! -f ${config_file} ]]; then
    echo "[vault] Secret environment file is missing: ${config_file}" >&2
    exit 1
fi

if [[ ${EUID} -eq 0 ]]; then
    owner=$(stat -c '%U:%G' -- "${config_file}")
    mode=$(stat -c '%a' -- "${config_file}")
    if [[ ${owner} != root:www-data || ${mode} != 640 ]]; then
        echo "[vault] Secret environment file must be root:www-data mode 0640." >&2
        exit 1
    fi
fi

allowed_keys=(
    SUFFICIT_SECRET_DATABASE_CONNECTION_STRING
    SUFFICIT_SECRET_IDENTITY_CERTIFICATES_SIGNING_PASSWORD
    SUFFICIT_SECRET_IDENTITY_CERTIFICATES_ENCRYPTION_PASSWORD
    SUFFICIT_SECRET_VAULT_KEK_CERTIFICATE_PASSWORD
    SUFFICIT_SECRET_IDENTITY_HUMAN_VERIFICATION_SECRET_KEY
    SUFFICIT_SECRET_IDENTITY_EXTERNAL_PROVIDERS_GOOGLE_CLIENT_ID
    SUFFICIT_SECRET_IDENTITY_EXTERNAL_PROVIDERS_GOOGLE_CLIENT_SECRET
    SUFFICIT_SECRET_IDENTITY_EXTERNAL_PROVIDERS_GITHUB_CLIENT_ID
    SUFFICIT_SECRET_IDENTITY_EXTERNAL_PROVIDERS_GITHUB_CLIENT_SECRET
    SUFFICIT_SECRET_IDENTITY_EXTERNAL_PROVIDERS_FACEBOOK_CLIENT_ID
    SUFFICIT_SECRET_IDENTITY_EXTERNAL_PROVIDERS_FACEBOOK_CLIENT_SECRET
    SUFFICIT_SECRET_IDENTITY_SMTP_PASSWORD
    SUFFICIT_SECRET_EXCHANGE_RABBITMQ_PASSWORD
)

is_allowed() {
    local candidate=$1 allowed
    for allowed in "${allowed_keys[@]}"; do
        [[ ${candidate} == "${allowed}" ]] && return 0
    done
    return 1
}

configured=0
while IFS= read -r line || [[ -n ${line} ]]; do
    [[ -z ${line} || ${line} == \#* ]] && continue
    if [[ ${line} == [[:space:]]* ]]; then
        echo "[vault] Leading whitespace is not allowed in the secret environment file." >&2
        exit 1
    fi
    if [[ ${line} != *=* ]]; then
        echo "[vault] Invalid line in secret environment file." >&2
        exit 1
    fi
    key=${line%%=*}
    value=${line#*=}
    if ! is_allowed "${key}"; then
        echo "[vault] Unsupported secret environment key: ${key}" >&2
        exit 1
    fi
    if [[ -z ${value} ]]; then
        echo "[vault] Empty value for ${key}." >&2
        exit 1
    fi
    configured=$((configured + 1))
done < "${config_file}"

echo "[vault] Secret environment file is valid (${configured} configured entries)."
