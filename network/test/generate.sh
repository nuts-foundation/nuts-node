# Generate CA
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1825 -out ca.pem -subj "/CN=Root CA"

# Generate node
openssl genrsa -out localhost.key 2048
openssl req -new -key localhost.key -out localhost.csr -subj "/CN=localhost"
openssl x509 -req -in localhost.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
-out localhost.pem -days 825 -sha256 -extfile localhost.ext

# Copy and clean up
cat localhost.pem > certificate-and-key.pem
cat localhost.key >> certificate-and-key.pem
cat ca.pem > truststore.pem

rm localhost.csr
rm localhost.pem
rm localhost.key
rm ca.pem
rm ca.key
rm ca.srl