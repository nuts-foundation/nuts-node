package grpc

import (
	"context"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"net/url"
	"testing"
)

const certAsPEM = `-----BEGIN CERTIFICATE-----
MIIDJjCCAg6gAwIBAgIJAJES+D3F7kfeMA0GCSqGSIb3DQEBCwUAMBIxEDAOBgNV
BAMMB1Jvb3QgQ0EwHhcNMjEwMTI2MTE1MzUwWhcNMjMwNTAxMTE1MzUwWjAUMRIw
EAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDVd35cCx0ald4nLbBKRli8Hfsl0uuEzkfGRtZKKW1pYJ4f/OpHwdW7Kvu17pqo
t2VMH+VCcZNfqh4MyDeuGocLkqm8Rj13jUZrJbvbTqzzj3685BWFsNg/TUAmEUBi
9wjKbaJgMcR0TTd4Ab9ux6qgIltR0kGM8v8I3kuEskToSkUJeCBxravvRUvmpe/F
5V1XdYvh+ckX8i8PujmzwWVezV5vT1wXKTVgSfhE+U/C1iNlUS58rbxQ76X40Y6g
4SMqdtyhsN1L4vYYrmeFiXqGCN2kwoXdIKLec7btdi3A/JgBypigwfR4pOqaBLsr
t1Vh+80QRqU39Jlq+HHT2bWnAgMBAAGjfTB7MCwGA1UdIwQlMCOhFqQUMBIxEDAO
BgNVBAMMB1Jvb3QgQ0GCCQCcbryLrV3pnTAJBgNVHRMEAjAAMAsGA1UdDwQEAwIE
8DAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwFAYDVR0RBA0wC4IJbG9j
YWxob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQCgUqk+5JyMnc9u8YVex3byVwoqBzsb
6Ni/TjDRsuFNIdJk4DPogF6Uzfc7tMr/nmFtiWNwrkOwjvC2StXUeCwVt6Sj51oj
qMLwpds9lcJZelsO/rar0mIiuradUUrISz9DTBqC/aE2hsRw0i4m/wF+slVQY7Aa
ZnECVkHdrKGz6OMFF8uU9t7N+xbzx5nFswEbJXw4AjTklXlyHeyuC0y09ZmWcUDs
16Gop6VMff6NkShfyUP3EPtvR4Mr33BDAXl8ePp6BFQFd1+IzBY//gfnNBObOqlA
zG0zvbFZM8oAu/AWf85MH4Ex06cbsimNUsJqu/cx4rDzqNF5iC2uKfKJ
-----END CERTIFICATE-----`

func Test_tlsOffloadingAuthenticator(t *testing.T) {
	auth := tlsOffloadingAuthenticator{clientCertHeaderName: "cert"}
	serverStream := &stubServerStream{}

	encodedCert := url.QueryEscape(certAsPEM)
	contextWithMD := func(cert string) context.Context {
		md := metadata.New(map[string]string{
			"cert": cert,
		})
		return metadata.NewIncomingContext(context.Background(), md)
	}

	t.Run("Intercept", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			var peerInfo *peer.Peer
			var success bool
			serverStream.ctx = contextWithMD(encodedCert)

			err := auth.Intercept(nil, serverStream, nil, func(srv interface{}, wrappedStream grpc.ServerStream) error {
				peerInfo, success = peer.FromContext(wrappedStream.Context())
				return nil
			})

			assert.NoError(t, err)
			assert.True(t, success)
			assert.NotNil(t, peerInfo)
			assert.Len(t, peerInfo.AuthInfo.(credentials.TLSInfo).State.PeerCertificates, 1)
			assert.Equal(t, credentials.PrivacyAndIntegrity, peerInfo.AuthInfo.(credentials.TLSInfo).CommonAuthInfo.SecurityLevel)
		})
		t.Run("auth fails", func(t *testing.T) {
			serverStream.ctx = contextWithMD("invalid cert")

			err := auth.Intercept(nil, serverStream, nil, func(srv interface{}, wrappedStream grpc.ServerStream) error {
				t.Fatal("should not be called")
				return nil
			})

			assert.Error(t, err)
		})
	})
	t.Run("Authenticate", func(t *testing.T) {
		t.Run("missing header", func(t *testing.T) {
			serverStream.ctx = metadata.NewIncomingContext(context.Background(), metadata.MD{})

			certs, err := auth.authenticate(serverStream)

			assert.EqualError(t, err, "expected exactly 1 value for header 'cert' (found 0)")
			assert.Nil(t, certs)
		})
		t.Run("invalid URL encoding", func(t *testing.T) {
			serverStream.ctx = contextWithMD("%%%")

			certs, err := auth.authenticate(serverStream)

			assert.EqualError(t, err, "TLS client header escaping is invalid")
			assert.Nil(t, certs)
		})
		t.Run("invalid URL encoding", func(t *testing.T) {
			serverStream.ctx = contextWithMD("not a certificate")

			certs, err := auth.authenticate(serverStream)

			assert.EqualError(t, err, "invalid client certificate(s) in header: unable to decode PEM encoded data")
			assert.Nil(t, certs)
		})
		t.Run("header is empty", func(t *testing.T) {
			serverStream.ctx = contextWithMD("")

			certs, err := auth.authenticate(serverStream)

			assert.EqualError(t, err, "expected exactly 1 client certificate in header, found 0")
			assert.Nil(t, certs)
		})
		t.Run("multiple certs", func(t *testing.T) {
			serverStream.ctx = contextWithMD(url.QueryEscape(certAsPEM + "\n" + certAsPEM))

			certs, err := auth.authenticate(serverStream)

			assert.EqualError(t, err, "expected exactly 1 client certificate in header, found 2")
			assert.Nil(t, certs)
		})
	})

}
