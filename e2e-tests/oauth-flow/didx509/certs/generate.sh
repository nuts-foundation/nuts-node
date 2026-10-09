#!/usr/bin/env bash
# Generates a certificate chain that mirrors PKIoverheid G4 UZI server certificates (issued by CIBG from November 2026):
# - root CA -> issuing (TSP) CA -> server certificate, all RSA 4096
# - RSASSA-PSS signatures with SHA-512, MGF1 and a 64-byte salt
# - subject C/ST/L/O/serialNumber/CN, SAN dNSName + UZI otherName (2.5.5.5) + permanentIdentifier (URA)
# - keyUsage digitalSignature+keyEncipherment, EKU serverAuth+clientAuth, G4 policy OIDs
# The identity values match the assertions in ../run-test.sh (URA 00001, "Because We Care", Healthland).
#
# After running, update the did:x509 ca-fingerprint in ../discovery.json and ../accesspolicy.json with the printed value.
# Requires OpenSSL 3.x.
set -euo pipefail
cd "$(dirname "$0")"

PSS="-sha512 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:64 -sigopt rsa_mgf1_md:sha512"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$TMP/root.key" 2>/dev/null
openssl req -x509 -new -key "$TMP/root.key" $PSS -days 3650 \
  -subj "/C=NL/O=Staat der Nederlanden/CN=Fake G4 Root Priv G-TLS" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$TMP/root.pem"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$TMP/tsp.key" 2>/dev/null
openssl req -new -key "$TMP/tsp.key" -sha512 -subj "/C=NL/O=CIBG/CN=Fake UZI Server - G4 PKIo Priv G-TLS SYS" -out "$TMP/tsp.csr"
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$TMP/tsp.ext"
openssl x509 -req -in "$TMP/tsp.csr" -CA "$TMP/root.pem" -CAkey "$TMP/root.key" -CAcreateserial $PSS -days 3650 \
  -extfile "$TMP/tsp.ext" -out "$TMP/tsp.pem" 2>/dev/null

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out nodeA.key 2>/dev/null
openssl req -new -key nodeA.key -sha512 -subj "/C=NL/ST=Healthland/L=Healthland/O=Because We Care/serialNumber=0/CN=nodeA" -out "$TMP/nodeA.csr"
cat > "$TMP/nodeA.ext" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
certificatePolicies=2.16.528.1.1003.1.2.44.15.35.11,0.4.0.2042.1.1
subjectAltName=DNS:nodeA,otherName:2.5.5.5;IA5STRING:2.16.528.1.1003.1.3.5.5.5-1-0-S-00001-00.000-0,otherName:1.3.6.1.5.5.7.8.3;SEQUENCE:permid
[permid]
identifierValue=UTF8:00001
assigner=OID:2.16.528.1.1007.3.3
EOF
openssl x509 -req -in "$TMP/nodeA.csr" -CA "$TMP/tsp.pem" -CAkey "$TMP/tsp.key" -CAcreateserial $PSS -days 3650 \
  -extfile "$TMP/nodeA.ext" -out nodeA.pem 2>/dev/null

cat nodeA.pem "$TMP/tsp.pem" "$TMP/root.pem" > nodeA-chain.pem
openssl verify -CAfile "$TMP/root.pem" -untrusted "$TMP/tsp.pem" nodeA.pem

FINGERPRINT=$(openssl x509 -in "$TMP/tsp.pem" -outform DER | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
echo "did:x509 ca-fingerprint (issuing CA): $FINGERPRINT"
echo "Update the 'pattern' in discovery.json and accesspolicy.json to: ^did:x509:0:sha256:${FINGERPRINT}::.*$"
