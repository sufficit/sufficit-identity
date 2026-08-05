#!/bin/bash
####################################
##  SUFFICIT BASH SCRIPT
##  ALL RIGHTS RESERVED (2026) SUFFICIT SOLUCOES EM TECNOLOGIA DA INFORMACAO
##  Version 2.0.0 — installs the Sufficit Identity STS (OpenIddict) as a
##  systemd service. Run from the app root (/opt/sufficit-identity).
##  2026-07-28 - created
####################################

set -euo pipefail

APPTITLE=sufficit-identity
ROOTDIR=/opt/${APPTITLE}
CONFIGDIR=/etc/sufficit/identity
LEGACYCONFIGDIR=/etc/${APPTITLE}

# Ensure the runtime user exists
if ! id -u dotnetuser >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin dotnetuser
    echo "[install] Created user dotnetuser"
fi

# Add dotnetuser to www-data group so the Unix socket is accessible by nginx
usermod -aG www-data dotnetuser 2>/dev/null || true

# Fix permissions (prestart.sh also does this, but run here for first install)
chown -R dotnetuser:www-data "${ROOTDIR}"
chmod 755 "${ROOTDIR}"/helpers/*.sh

# Install the non-secret operational hardening overlay once. Deliberately do
# not overwrite it on upgrades: CSP and MFA progress are environment state,
# not release defaults.
install -d -o root -g www-data -m 0750 "${CONFIGDIR}"
if [ ! -f "${CONFIGDIR}/hardening.env" ]; then
    if [ -f "${LEGACYCONFIGDIR}/hardening.env" ]; then
        install -o root -g www-data -m 0640 \
            "${LEGACYCONFIGDIR}/hardening.env" \
            "${CONFIGDIR}/hardening.env"
        echo "[install] Migrated ${LEGACYCONFIGDIR}/hardening.env to ${CONFIGDIR}/hardening.env"
    else
        install -o root -g www-data -m 0640 \
            "${ROOTDIR}/helpers/hardening.env.template" \
            "${CONFIGDIR}/hardening.env"
        echo "[install] Created ${CONFIGDIR}/hardening.env"
    fi
else
    echo "[install] Preserved existing ${CONFIGDIR}/hardening.env"
fi

# Releases may introduce new non-secret rollout gates. Preserve every existing
# operator value, but append keys that are missing from an older environment
# file using the secure defaults from the versioned template. This keeps the
# status helper explicit after upgrades without silently enabling anything.
missing_defaults=0
while IFS= read -r default_line; do
    case ${default_line} in
        ''|'#'*) continue ;;
        *=*) ;;
        *) continue ;;
    esac

    default_key=${default_line%%=*}
    if ! awk -F= -v wanted="${default_key}" '
        $1 == wanted { found=1 }
        END { exit found ? 0 : 1 }
    ' "${CONFIGDIR}/hardening.env"
    then
        printf '%s\n' "${default_line}" >> "${CONFIGDIR}/hardening.env"
        missing_defaults=$((missing_defaults + 1))
    fi
done < "${ROOTDIR}/helpers/hardening.env.template"

if [ "${missing_defaults}" -gt 0 ]; then
    echo "[install] Added ${missing_defaults} missing hardening default(s); existing values preserved"
fi

# Syslog configuration (routes [sufficit][identity] logs to a dedicated file)
mkdir -p /var/log/sufficit
install -o root -g root -m 0644 \
    "${ROOTDIR}/helpers/syslog.conf" \
    /etc/rsyslog.d/40-${APPTITLE}.conf
systemctl restart rsyslog 2>/dev/null || true

# Install a regular unit file rather than a symlink into the active release.
# That keeps systemd manageable if the /opt/sufficit-identity release symlink
# is rolled back to an older package that did not contain helpers yet.
install -o root -g root -m 0644 \
    "${ROOTDIR}/helpers/${APPTITLE}.service" \
    /etc/systemd/system/${APPTITLE}.service
systemctl daemon-reload
systemctl enable "${APPTITLE}"

echo "[install] Service installed. Run: systemctl start ${APPTITLE}"
