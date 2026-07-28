#!/bin/bash
####################################
##  SUFFICIT BASH SCRIPT
##  ALL RIGHTS RESERVED (2026) SUFFICIT SOLUCOES EM TECNOLOGIA DA INFORMACAO
##  Version 2.0.0 — installs the Sufficit Identity STS (OpenIddict) as a
##  systemd service. Run from the app root (/opt/sufficit-identity).
##  2026-07-28 - created
####################################

set -e

APPTITLE=sufficit-identity
ROOTDIR=/opt/${APPTITLE}

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

# Syslog configuration (routes [sufficit][identity] logs to a dedicated file)
mkdir -p /var/log/sufficit
ln -sf "${ROOTDIR}/helpers/syslog.conf" /etc/rsyslog.d/40-${APPTITLE}.conf
systemctl restart rsyslog 2>/dev/null || true

# Install the systemd service
ln -sf "${ROOTDIR}/helpers/${APPTITLE}.service" /etc/systemd/system/${APPTITLE}.service
systemctl daemon-reload
systemctl enable ${APPTITLE}

echo "[install] Service installed. Run: systemctl start ${APPTITLE}"
