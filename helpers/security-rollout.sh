#!/bin/bash
####################################
##  SUFFICIT IDENTITY SECURITY ROLLOUT
##  Applies explicit, reversible rollout gates to the systemd environment.
####################################

set -euo pipefail

CONFIG_FILE=${IDENTITY_HARDENING_ENV:-/etc/sufficit/identity/hardening.env}
BACKUP_CREATED=false

usage() {
    cat <<'EOF'
Usage: security-rollout.sh <command> [argument]

Commands:
  status                         Show the non-secret rollout switches.
  prepare-csp [report-uri]       Enable CSP in Report-Only mode.
  enforce-csp                    Change CSP from reporting to enforcement.
  enforce-mfa --confirmed        Require MFA for administrative endpoints.
  disable-mfa                    Emergency rollback for the MFA gate.
  enable-jarm                    Advertise and accept signed JARM responses.
  disable-jarm                   Disable JARM response modes.

Set IDENTITY_HARDENING_ENV to operate on a file other than
/etc/sufficit/identity/hardening.env. Restart the service after a change.
EOF
}

require_config() {
    if [[ ! -f ${CONFIG_FILE} ]]; then
        echo "[rollout] Configuration not found: ${CONFIG_FILE}" >&2
        exit 1
    fi
}

read_value() {
    local key=$1
    awk -F= -v wanted="${key}" '$1 == wanted { value=substr($0, index($0, "=") + 1) } END { print value }' "${CONFIG_FILE}"
}

write_value() {
    local key=$1
    local value=$2
    local config_dir temporary backup

    config_dir=$(dirname -- "${CONFIG_FILE}")
    temporary=$(mktemp "${config_dir}/.hardening.env.XXXXXX")
    backup="${CONFIG_FILE}.bak"

    if [[ ${BACKUP_CREATED} == false ]]; then
        cp --preserve=mode,ownership "${CONFIG_FILE}" "${backup}"
        BACKUP_CREATED=true
    fi
    awk -v wanted="${key}" -v replacement="${key}=${value}" '
        BEGIN { replaced=0 }
        $0 ~ "^" wanted "=" {
            if (!replaced) print replacement
            replaced=1
            next
        }
        { print }
        END { if (!replaced) print replacement }
    ' "${CONFIG_FILE}" > "${temporary}"
    chmod --reference="${CONFIG_FILE}" "${temporary}"
    chown --reference="${CONFIG_FILE}" "${temporary}" 2>/dev/null || true
    mv -f -- "${temporary}" "${CONFIG_FILE}"
}

show_status() {
    local key
    for key in \
        Sufficit__Identity__RateLimit__Enabled \
        Sufficit__Identity__RateLimit__FailOnUntrustedProxy \
        Sufficit__Identity__Csp__Enabled \
        Sufficit__Identity__Csp__ReportOnly \
        Sufficit__Identity__Csp__ReportUri \
        Sufficit__Identity__Management__RequireMfa \
        Sufficit__Identity__Dpop__Enabled \
        Sufficit__Identity__Ciba__Enabled \
        Sufficit__Identity__Fapi2__Enabled \
        Sufficit__Identity__Jarm__Enabled \
        Sufficit__Identity__SharedSignals__Enabled
    do
        printf '%s=%s\n' "${key}" "$(read_value "${key}")"
    done
}

require_config

case ${1:-} in
    status)
        show_status
        ;;
    prepare-csp)
        report_uri=${2:-/security/csp-report}
        if [[ ${report_uri} != /* && ${report_uri} != http://* && ${report_uri} != https://* ]]; then
            echo "[rollout] report-uri must be same-origin (/path) or an absolute HTTP(S) URI." >&2
            exit 1
        fi
        write_value Sufficit__Identity__Csp__Enabled true
        write_value Sufficit__Identity__Csp__ReportOnly true
        write_value Sufficit__Identity__Csp__ReportUri "${report_uri}"
        echo "[rollout] CSP reporting prepared. Review violations before enforcement."
        ;;
    enforce-csp)
        if [[ $(read_value Sufficit__Identity__Csp__Enabled) != true ]]; then
            echo "[rollout] CSP must be enabled before enforcement." >&2
            exit 1
        fi
        if [[ -z $(read_value Sufficit__Identity__Csp__ReportUri) ]]; then
            echo "[rollout] Configure ReportUri and calibrate the policy before enforcement." >&2
            exit 1
        fi
        write_value Sufficit__Identity__Csp__ReportOnly false
        echo "[rollout] CSP enforcement enabled."
        ;;
    enforce-mfa)
        if [[ ${2:-} != --confirmed ]]; then
            echo "[rollout] Refusing to enable MFA without --confirmed." >&2
            echo "Confirm every administrator has completed 2FA and a rollback path exists." >&2
            exit 1
        fi
        write_value Sufficit__Identity__Management__RequireMfa true
        echo "[rollout] Administrative MFA requirement enabled."
        ;;
    disable-mfa)
        write_value Sufficit__Identity__Management__RequireMfa false
        echo "[rollout] Administrative MFA requirement disabled."
        ;;
    enable-jarm)
        write_value Sufficit__Identity__Jarm__Enabled true
        echo "[rollout] JARM response modes enabled."
        ;;
    disable-jarm)
        write_value Sufficit__Identity__Jarm__Enabled false
        echo "[rollout] JARM response modes disabled."
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

if [[ ${1:-} != status ]]; then
    echo "[rollout] Backup: ${CONFIG_FILE}.bak"
    echo "[rollout] Apply with: systemctl restart sufficit-identity"
fi
