#!/usr/bin/env sh
set -eu

CERT_DIR="${ONE_MIND_CERT_DIR:-/app/certs}"
CERT_PATH="$CERT_DIR/server.crt"
KEY_PATH="$CERT_DIR/server.key"
HOST="${ONE_MIND_HOST:-0.0.0.0}"
PORT="${ONE_MIND_PORT:-8443}"
TLS_MODE="${ONE_MIND_TLS_MODE:-internal}"

mkdir -p "$CERT_DIR" "${ONE_MIND_DATA_DIR:-/app/data}"

if [ "$TLS_MODE" = "off" ]; then
  echo "ONE_MIND aktif di http://$HOST:$PORT di belakang reverse proxy TLS"
  exec uvicorn app.main:app --host "$HOST" --port "$PORT" --proxy-headers --forwarded-allow-ips='*'
fi

if [ "$TLS_MODE" != "internal" ]; then
  echo "ONE_MIND_TLS_MODE harus 'internal' atau 'off'." >&2
  exit 1
fi

if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
  python /app/scripts/generate_cert.py "$CERT_PATH" "$KEY_PATH"
fi

echo "ONE_MIND aktif di https://localhost:$PORT"
echo "Sertifikat TLS: $CERT_PATH"
exec uvicorn app.main:app --host "$HOST" --port "$PORT" --ssl-certfile "$CERT_PATH" --ssl-keyfile "$KEY_PATH"
