#!/usr/bin/env bash

# Generate JWT ID Token signed with OpenSSL
# Usage: ./generate-jwt.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRIVATE_KEY="$SCRIPT_DIR/certs/dezi_signing.key"
CERT_FILE="$SCRIPT_DIR/certs/dezi_signing.pem"

# Base64 URL encode function
base64url_encode() {
    openssl base64 -e -A | tr '+/' '-_' | tr -d '='
}

# Generate certificate if it doesn't exist
if [ ! -f "$CERT_FILE" ]; then
    echo "Generating self-signed certificate..."
    openssl req -new -x509 -key "$PRIVATE_KEY" -out "$CERT_FILE" -days 365 \
        -subj "/CN=localhost"
fi

# Extract public key modulus for kid calculation
# Calculate SHA1 hash of the DER-encoded certificate and base64 encode it
KID=$(openssl x509 -in "$CERT_FILE" -outform DER | openssl dgst -sha1 -binary | base64)

# Extract certificate for x5c (strip headers and newlines)
X5C=$(grep -v "BEGIN CERTIFICATE" "$CERT_FILE" | grep -v "END CERTIFICATE" | tr -d '\n')

# Get current time and calculate exp/nbf
NOW=$(date +%s)
NBF=$NOW
EXP=$((NOW + 3600))  # 1 hour from now

# JWT Header
HEADER=$(cat <<EOF | jq -c .
{
  "alg": "RS256",
  "kid": "$KID",
  "typ": "JWT"
}
EOF
)

# JWT Payload
PAYLOAD=$(cat <<EOF | jq -c .
{
  "Dezi_id": "900000009",
  "aud": [
    "006fbf34-a80b-4c81-b6e9-593600675fb2"
  ],
  "exp": $EXP,
  "initials": "B.B.",
  "iss": "https://max.proeftuin.Dezi-online.rdobeheer.nl",
  "json_schema": "https://max.proeftuin.Dezi-online.rdobeheer.nl/json_schema.json",
  "loa_Dezi": "http://eidas.europa.eu/LoA/high",
  "loa_authn": "http://eidas.europa.eu/LoA/high",
  "nbf": $NBF,
  "relations": [
    {
      "entity_name": "Zorgaanbieder",
      "roles": [
        "01.041",
        "30.000",
        "01.010",
        "01.011"
      ],
      "ura": "87654321"
    }
  ],
  "surname": "Jansen",
  "surname_prefix": "van der",
  "x5c": [
    "$X5C"
  ]
}
EOF
)

# Base64url encode header and payload
HEADER_B64=$(echo -n "$HEADER" | base64url_encode)
PAYLOAD_B64=$(echo -n "$PAYLOAD" | base64url_encode)

# Create signing input
SIGNING_INPUT="${HEADER_B64}.${PAYLOAD_B64}"

# Sign with RS256
SIGNATURE=$(echo -n "$SIGNING_INPUT" | openssl dgst -sha256 -sign "$PRIVATE_KEY" -binary | base64url_encode)

# Construct JWT
JWT="${SIGNING_INPUT}.${SIGNATURE}"

# Output the JWT
echo "$JWT"
