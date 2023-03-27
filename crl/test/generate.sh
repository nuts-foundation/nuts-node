#!/bin/zsh

## Init
rm -r data
mkdir data
cp openssl.conf data/root-ca.conf
cd data
mkdir certs db private
touch db/index db/indexSub
echo 01  > db/serial # init serial to 01 for deterministic serial assignment
echo 1001 > db/crlnumber

## Generate Root CA
# serial 01 - Root
openssl req -new \
    -config root-ca.conf \
    -out root-ca.csr \
    -keyout private/root-ca.key

# sign 01
openssl ca -selfsign \
    -config root-ca.conf \
    -in root-ca.csr \
    -out root-ca.crt \
    -notext -batch \
    -extensions ca_ext

# ## Generate Intermediate CAs
# serial 02 - Root-IntA
openssl req -new \
    -subj "/CN=Intermediate A CA" \
    -config root-ca.conf \
    -out intA-ca.csr \
    -keyout private/intA-ca.key

# serial 03 - Root-IntB
openssl req -new \
    -subj "/CN=Intermediate B CA" \
    -config root-ca.conf \
    -out intB-ca.csr \
    -keyout private/intB-ca.key

# sign 02,03
openssl ca -notext -batch \
    -config root-ca.conf \
    -extensions sub_ca_ext \
    -infiles intA-ca.csr intB-ca.csr > int-ca.crt

## Generate Leaf Certs
# serial 04 - Root-IntA-Valid
openssl req -new \
    -subj "/CN=CertA Valid" \
    -config root-ca.conf \
    -out leafA1.csr \
    -keyout private/leafA1.key
# serial 05 - Root-IntA-Revoked
openssl req -new \
    -subj "/CN=CertA Revoked" \
    -config root-ca.conf \
    -out leafA2.csr \
    -keyout private/leafA2.key
# sign 04,05 (writes to db/indexSub that is used for the sub-ca CRLs)
openssl ca -notext -batch \
    -name sub-ca \
    -config root-ca.conf \
    -keyfile private/intA-ca.key -cert certs/02.pem \
    -extensions intA_ext \
    -outdir certs \
    -infiles leafA1.csr leafA2.csr > /dev/null

# serial 06 - Root-IntA-Expired
openssl req -new \
    -subj "/CN=CertA Expired" \
    -config root-ca.conf \
    -out leafA3.csr \
    -keyout private/leafA3.key
# sign 06
openssl ca -notext -batch \
    -name sub-ca \
    -days 1 \
    -config root-ca.conf \
    -keyfile private/intA-ca.key -cert certs/02.pem \
    -extensions intA_ext \
    -outdir certs \
    -infiles leafA3.csr > /dev/null


# serial 07 - Root-IntB-Valid
openssl req -new \
    -subj "/CN=CertB Valid" \
    -config root-ca.conf \
    -out leafB1.csr \
    -keyout private/leafB1.key
openssl ca \
    -name sub-ca \
    -config root-ca.conf \
    -keyfile private/intB-ca.key -cert certs/03.pem \
    -extensions intB_ext \
    -outdir certs \
    -notext -batch \
    -in leafB1.csr  > /dev/null


## Generate CRLs
# generate empty CRL for Intermediate B
openssl ca -gencrl \
    -name sub-ca \
    -config root-ca.conf \
    -keyfile private/intB-ca.key -cert certs/03.pem \
    -out intB.crl

# revoke 05 and generate CRL for Intermediate A
openssl ca \
    -name sub-ca \
    -config root-ca.conf \
    -keyfile private/intA-ca.key -cert certs/02.pem \
    -revoke certs/05.pem \
    -crl_reason keyCompromise
openssl ca -gencrl \
    -name sub-ca \
    -keyfile private/intA-ca.key -cert certs/02.pem \
    -config root-ca.conf \
    -out intA.crl

# revoke Intermediate B CA, which has serial 03, and generate CLR for Root CA
openssl ca \
    -config root-ca.conf \
    -revoke certs/03.pem \
    -crl_reason keyCompromise
openssl ca -gencrl \
    -config root-ca.conf \
    -out root-ca.crl


## Copy data and cleanup
cd ..

cat data/int-ca.crt data/root-ca.crt ../../network/test/pkioverheid-server-bundle.pem > truststore.pem
cat data/certs/04.pem data/private/leafA1.key > A-valid.pem
cat data/certs/05.pem data/private/leafA2.key > A-revoked.pem
cat data/certs/06.pem data/private/leafA3.key > A-expired.pem
cat data/certs/07.pem data/private/leafB1.key > B-valid_revoked-CA.pem

openssl crl \
    -inform pem -in data/root-ca.crl \
    -outform der -out RootCALatest.crl

openssl crl \
    -inform pem -in data/intA.crl \
    -outform der -out IntermediateCAALatest.crl

openssl crl \
    -inform pem -in data/intB.crl \
    -outform der -out IntermediateCABLatest.crl

rm -r data
