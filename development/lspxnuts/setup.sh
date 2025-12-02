#!/usr/bin/env bash

set -e

# Configuration
NUTS_NODE_URL="http://localhost:18081"
SUBJECT_NAME="${SUBJECT_NAME:-testsubject}"
CERT_CHAIN="./certs/localhost-chain.pem"
CERT_KEY="./certs/localhost.key"
ISSUER_CN="${ISSUER_CN:-CN=Fake UZI Root CA}"

echo "======================================"
echo "LSPxNuts Setup Script"
echo "======================================"
echo ""

echo "------------------------------------"
echo "Creating Nuts subject..."
echo "------------------------------------"
REQUEST="{\"subject\":\"${SUBJECT_NAME}\"}"
RESPONSE=$(echo $REQUEST | curl -s -X POST --data-binary @- ${NUTS_NODE_URL}/internal/vdr/v2/subject --header "Content-Type: application/json")

# Extract DID from response
DID=$(echo $RESPONSE | jq -r '.documents[0].id')

if [ -z "$DID" ] || [ "$DID" = "null" ]; then
  echo "ERROR: Failed to create subject or extract DID"
  echo "Response: $RESPONSE"
  exit 1
fi

echo "✓ Subject created successfully"
echo "  Subject: ${SUBJECT_NAME}"
echo "  DID: ${DID}"
echo ""

echo "------------------------------------"
echo "Issuing X509Credential..."
echo "------------------------------------"

# Check if certificate files exist
if [ ! -f "$CERT_CHAIN" ]; then
  echo "ERROR: Certificate chain not found at $CERT_CHAIN"
  exit 1
fi

if [ ! -f "$CERT_KEY" ]; then
  echo "ERROR: Certificate key not found at $CERT_KEY"
  exit 1
fi

# Issue X509 credential using go-didx509-toolkit Docker image
CREDENTIAL=$(docker run \
  --rm \
  -v "$(pwd)/${CERT_CHAIN}:/cert-chain.pem:ro" \
  -v "$(pwd)/${CERT_KEY}:/cert-key.key:ro" \
  nutsfoundation/go-didx509-toolkit:main \
  vc "/cert-chain.pem" "/cert-key.key" "${ISSUER_CN}" "${DID}")

if [ -z "$CREDENTIAL" ]; then
  echo "ERROR: Failed to generate X509Credential"
  exit 1
fi

echo "✓ X509Credential generated"
echo ""

echo "------------------------------------"
echo "Loading credential into wallet..."
echo "------------------------------------"

# Store credential in wallet
HTTP_CODE=$(echo "\"${CREDENTIAL}\"" | curl -s -o /dev/null -w "%{http_code}" \
  -X POST --data-binary @- \
  ${NUTS_NODE_URL}/internal/vcr/v2/holder/${SUBJECT_NAME}/vc \
  -H "Content-Type:application/json")

if [ "$HTTP_CODE" -eq 204 ]; then
  echo "✓ X509Credential successfully stored in wallet"
else
  echo "ERROR: Failed to load X509Credential in wallet (HTTP $HTTP_CODE)"
  exit 1
fi

echo ""
echo "======================================"
echo "Setup completed successfully!"
echo "======================================"
echo "Subject: ${SUBJECT_NAME}"
echo "DID: ${DID}"
echo ""
echo "You can now use this credential for OAuth2 flows."
echo ""

