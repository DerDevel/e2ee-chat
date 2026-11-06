#!/usr/bin/env bash
# Generate a self-signed TLS certificate for local development and print the
# SHA-256 pin clients can use to authenticate the server without a CA.
set -euo pipefail

out_dir="${1:-.}"
days="${DAYS:-825}"

openssl ecparam -name prime256v1 -genkey -noout -out "$out_dir/server.key"
openssl req -new -x509 \
  -key "$out_dir/server.key" \
  -out "$out_dir/server.crt" \
  -days "$days" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 "$out_dir/server.key"

pin="$(openssl x509 -in "$out_dir/server.crt" -noout -fingerprint -sha256 \
  | cut -d= -f2 | tr -d ':' | tr 'A-Z' 'a-z')"

echo "Generated $out_dir/server.crt and $out_dir/server.key"
echo
echo "Trust the server from clients with:"
echo "  export E2EE_TLS_PIN=$pin"
