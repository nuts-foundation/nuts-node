# Test files
The standard Go HTTPS testserver's TLS certificate is valid for 127.0.0.1, not localhost.
But did:web DIDs can't contain an IP address, so we need a certificate for localhost. This is found in cert.pem and key.pem.

`cert.pem` and `key.pem` were generated using (given GOROOT `/usr/local/go`):

```shell
go run /usr/local/go/src/crypto/tls/generate_cert.go  --rsa-bits 2048 --host 127.0.0.1,::1,localhost,example.com --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
```