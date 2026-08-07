#!/bin/bash
####################################
##  SUFFICIT BASH SCRIPT
##  ALL RIGHTS RESERVED (2026) SUFFICIT SOLUCOES EM TECNOLOGIA DA INFORMACAO
##  Version 2.1.0 — persistent OpenIddict signing/encryption certificate
##  2026-07-28 - created for the new Sufficit.Identity.Server (OpenIddict)
####################################

set -e

APPTITLE=sufficit-identity
ROOTDIR=/opt/${APPTITLE}
CONFIGDIR=/etc/sufficit/identity
# Releases are selected through the /opt/sufficit-identity symlink. Resolve it
# before creating or fixing files so a first-start certificate is owned by the
# service account in the release directory, not by root in an unreachable
# target path.
RELEASEDIR=$(readlink -f "${ROOTDIR}")

# ---- OpenIddict certificate -------------------------------------------------
# The signing/encryption key is application state, not a TLS certificate and
# not a release artifact. Every Identity replica must receive the same PFX or
# clients can fetch JWKS from one node and receive a token signed by another.
# Keep the canonical copy outside the release tree so atomic deployments and
# rollbacks cannot rotate it accidentally.
CERT_STORE=${CONFIGDIR}/certificate.pfx
CERT_DST=${RELEASEDIR}/certificate.pfx
RUNTIME_ENVIRONMENT=${ASPNETCORE_ENVIRONMENT:-Production}

install -d -o root -g www-data -m 0750 "${CONFIGDIR}"

if [ -f "${CERT_STORE}" ]; then
    # Always overwrite the release-local copy from the persistent authority.
    # This also repairs a partially populated release before the process starts.
    install -o dotnetuser -g www-data -m 0640 "${CERT_STORE}" "${CERT_DST}"
    echo "[prestart] Persistent application certificate installed in active release"
elif [ -f "${CERT_DST}" ]; then
    # One-time bootstrap for an operator-supplied release. Subsequent releases
    # are populated from CERT_STORE above.
    install -o root -g www-data -m 0640 "${CERT_DST}" "${CERT_STORE}"
    chown dotnetuser:www-data "${CERT_DST}"
    chmod 0640 "${CERT_DST}"
    echo "[prestart] Application certificate persisted outside the release tree"
elif [ "${RUNTIME_ENVIRONMENT}" = "Development" ]; then
    # Development remains self-contained. Production deliberately fails closed
    # instead of generating a node-local key that would break HA and invalidate
    # every token after a restart.
    echo "[prestart] No development PFX found — generating self-signed certificate"
    openssl req -x509 -newkey rsa:2048 \
        -keyout /tmp/_identity-key.pem \
        -out /tmp/_identity-cert.pem \
        -days 365 -nodes \
        -subj '/CN=identity.example.com' 2>/dev/null
    openssl pkcs12 -export \
        -in /tmp/_identity-cert.pem \
        -inkey /tmp/_identity-key.pem \
        -out "${CERT_DST}" \
        -passout pass:TestCerts2026 2>/dev/null
    rm -f /tmp/_identity-key.pem /tmp/_identity-cert.pem
    echo "[prestart] Self-signed certificate generated at ${CERT_DST}"
else
    echo "[prestart] ERROR: ${CERT_STORE} is required in ${RUNTIME_ENVIRONMENT}." >&2
    echo "[prestart] Provision the same OpenIddict PFX on every Identity replica." >&2
    exit 1
fi

# ---- Permissions ----
# The app runs as dotnetuser with group www-data (so nginx can read the Unix
# socket created by Kestrel at /run/sufficit-identity/identity.sock).
chown -R dotnetuser:www-data "${RELEASEDIR}"
chmod 755 "${RELEASEDIR}"/helpers/*.sh 2>/dev/null || true

echo "[prestart] Done"
