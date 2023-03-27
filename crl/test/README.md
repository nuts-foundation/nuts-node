
# Generate chain
`sh generate.sh` creates the trust chain using the configuration in `openssl.conf`. 

All sub/intermediate CAs use the same config and therefore same certificate administration. 
Revocations are currently only generated correctly because of the order of revocation and CRL generation.

# Errors?!?!
MacOS by default uses `LibreSSL` which doesn't work with this script.
Check the version using `openssl version`. This is tested with `OpenSSL 1.1.1t  7 Feb 2023` distributed by `Homebrew`

# Certificate chain

Certificate properties above are summarized as:
```
CommonName (that is on the certificate)
- serial: the certificate's serial number
- status: one of valid,revoked,expired
- CRL: the CRL issued by this cert
- Issues: ceritifcates issued by this cert. When revoked they appear on the listed CRL.
- File: the file the cert is in. Only leaf certs contain a private key.
```

The actual chain
```
Root CA
- serial: 01
- status: valid
- CRL: RootCALatest.crl
- Issues: Intermediate A CA, Intermediate B CA
- File: truststore.pem

Intermediate A CA
- serial: 02
- status: valid
- CRL: IntermediateCAALatest.crl
- Issues: CertA Valid, CertA Revoked, CertA Expired
- File: truststore.pem

Intermediate B CA
- serial: 03
- status: revoked
- CRL: IntermediateCABLatest.crl
- Issues: CertB Valid
- File: truststore.pem

CertA Valid
- serial: 04
- status: valid
- File: A-valid.pem

CertA Revoked
- serial: 05
- status: revoked
- File: A-revoked.pem

CertA Expired
- serial: 06
- status: expired
- File: A-expired.pem

CertB Valid
- serial: 07
- status: valid (but CA is revoked)
- File: B-valid_revoked-CA.pem
```

`truststore.pem` contains in order:
- `Intermediate A CA`
- `Intermediate B CA`
- `Root CA`
- `/network/test/pkioverheid-server-bundle.pem`