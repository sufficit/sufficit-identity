#!/bin/sh
set -e

CERT_DIR=/etc/nginx/certs
CERT="$CERT_DIR/cert.pem"
KEY="$CERT_DIR/key.pem"

# Generate a self-signed cert on first boot if one doesn't exist.
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    echo "[gen-cert] Generating self-signed TLS certificate for local dev..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$KEY" -out "$CERT" \
        -days 365 \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        2>/dev/null
    echo "[gen-cert] Done."
fi

# Start nginx in foreground
exec nginx -g 'daemon off;'
