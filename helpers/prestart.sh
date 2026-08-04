#!/bin/bash
####################################
##  SUFFICIT BASH SCRIPT
##  ALL RIGHTS RESERVED (2026) SUFFICIT SOLUCOES EM TECNOLOGIA DA INFORMACAO
##  Version 2.0.0 — OpenIddict STS (replaces legacy Duende prestart)
##  2026-07-28 - created for the new Sufficit.Identity.Server (OpenIddict)
####################################

set -e

APPTITLE=sufficit-identity
ROOTDIR=/opt/${APPTITLE}

# ---- Certificate ----
# Copy the global Let's Encrypt PFX into the app directory so the STS can sign
# tokens with it. The PFX is generated/renewed by certbot + the export script
# at /etc/letsencrypt/live/sufficit.com.br/certificate.pfx.
# When no PFX is available (fresh install, test environment), a self-signed
# certificate is generated on the fly so the service starts.
CERT_SRC=/etc/letsencrypt/live/sufficit.com.br/certificate.pfx
CERT_DST=${ROOTDIR}/certificate.pfx

# Releases carry forward the exact signing certificate that matches the
# configured Certificates:Password. Never replace it with the global TLS PFX:
# that file may use a different password and is not necessarily the intended
# OpenIddict signing key. CERT_SRC is only a bootstrap source for a release
# that does not have a certificate yet.
if [ -f "${CERT_DST}" ]; then
    echo "[prestart] Existing application certificate preserved at ${CERT_DST}"
elif [ -f "${CERT_SRC}" ]; then
    yes | cp -rf "${CERT_SRC}" "${CERT_DST}" 2>/dev/null || true
    echo "[prestart] Certificate copied from ${CERT_SRC}"
else
    # Generate a self-signed cert for dev/test (no Let's Encrypt available).
    echo "[prestart] No PFX found — generating self-signed certificate"
    openssl req -x509 -newkey rsa:2048 \
        -keyout /tmp/_identity-key.pem \
        -out /tmp/_identity-cert.pem \
        -days 365 -nodes \
        -subj '/CN=identity.sufficit.com.br' 2>/dev/null
    openssl pkcs12 -export \
        -in /tmp/_identity-cert.pem \
        -inkey /tmp/_identity-key.pem \
        -out "${CERT_DST}" \
        -passout pass:TestCerts2026 2>/dev/null
    rm -f /tmp/_identity-key.pem /tmp/_identity-cert.pem
    echo "[prestart] Self-signed certificate generated at ${CERT_DST}"
fi

# ---- Permissions ----
# The app runs as dotnetuser with group www-data (so nginx can read the Unix
# socket created by Kestrel at /run/sufficit-identity/identity.sock).
chown -R dotnetuser:www-data "${ROOTDIR}"
chmod 755 "${ROOTDIR}"/helpers/*.sh 2>/dev/null || true

echo "[prestart] Done"
