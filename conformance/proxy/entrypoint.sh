#!/bin/sh
# Self-signed certificate for identity-op.test; the conformance suite does not
# validate the OP certificate in development mode.
set -e
mkdir -p /certs
if [ ! -f /certs/cert.pem ]; then
    apk add --no-cache openssl >/dev/null
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
        -keyout /certs/key.pem -out /certs/cert.pem \
        -subj "/CN=identity-op.test" \
        -addext "subjectAltName=DNS:identity-op.test" 2>/dev/null
fi
exec nginx -g 'daemon off;'
