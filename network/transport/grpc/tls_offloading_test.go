/*
 * Copyright (C) 2022 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package grpc

import (
	"context"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"net/url"
	"testing"
)

const certAsDER = "MIIBLDCB06ADAgECAgkAmIRh+hEybUEwCgYIKoZIzj0EAwIwEjEQMA4GA1UEAwwHUm9vdCBDQTAeFw0yMTAyMjIxMjI4MDJaFw0yMzA1MjgxMjI4MDJaMBAxDjAMBgNVBAMMBW5vZGVCMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDj3lVuuswobsBm1hpLWJ3occMPnHRv31Z84t4xzTePeqHZkWgwhdoffRoWDFonBeC/pPyIdYPnyImTZTVYx6oaMUMBIwEAYDVR0RBAkwB4IFbm9kZUIwCgYIKoZIzj0EAwIDSAAwRQIhAJvWKKcU/JCjcR/Ub4XDfmbAAFacq1bqeU/3BXU+K6cIAiB20w4Tq+wb3MvK6j/MGz+DHPW0V4PGREsMS/kfnzWdTw=="
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
const invalidCertAsPEM = `-----BEGIN CERTIFICATE-----
invalid
-----END CERTIFICATE-----`

func Test_tlsOffloadingAuthenticator(t *testing.T) {
	pkiMock := pki.NewMockValidator(gomock.NewController(t))
	auth := tlsOffloadingAuthenticator{clientCertHeaderName: "cert", pkiValidator: pkiMock}
	serverStream := &stubServerStream{}

	encodedCert := url.QueryEscape(certAsPEM)
	contextWithMD := func(cert string) context.Context {
		md := metadata.New(map[string]string{
			"cert": cert,
		})
		return metadata.NewIncomingContext(context.Background(), md)
	}

	t.Run("intercept", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			var peerInfo *peer.Peer
			var success bool
			serverStream.ctx = contextWithMD(encodedCert)
			pkiMock.EXPECT().Validate(gomock.Any())

			err := auth.intercept(nil, serverStream, nil, func(srv interface{}, wrappedStream grpc.ServerStream) error {
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

			err := auth.intercept(nil, serverStream, nil, func(srv interface{}, wrappedStream grpc.ServerStream) error {
				t.Fatal("should not be called")
				return nil
			})

			assert.Error(t, err)
		})
		t.Run("certificate revoked/banned", func(t *testing.T) {
			serverStream.ctx = contextWithMD(encodedCert)
			pkiMock.EXPECT().Validate(gomock.Any()).Return(errors.New("custom error"))

			err := auth.intercept(nil, serverStream, nil, func(srv interface{}, wrappedStream grpc.ServerStream) error {
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

			assert.EqualError(t, err, "unable to base64 decode client cert header: illegal base64 data at input byte 3")
			assert.Nil(t, certs)
		})
		t.Run("PEM: invalid certificate", func(t *testing.T) {
			serverStream.ctx = contextWithMD(url.QueryEscape(invalidCertAsPEM))

			certs, err := auth.authenticate(serverStream)

			assert.EqualError(t, err, "invalid client certificate(s) in header: unable to decode PEM encoded data")
			assert.Nil(t, certs)
		})
		t.Run("header is empty", func(t *testing.T) {
			serverStream.ctx = contextWithMD("")

			certs, err := auth.authenticate(serverStream)

			assert.EqualError(t, err, "unable to DER decode client cert: x509: malformed certificate")
			assert.Nil(t, certs)
		})
		t.Run("PEM: multiple certs", func(t *testing.T) {
			serverStream.ctx = contextWithMD(url.QueryEscape(certAsPEM + "\n" + certAsPEM))

			certs, err := auth.authenticate(serverStream)

			assert.EqualError(t, err, "expected exactly 1 client certificate in header, found 2")
			assert.Nil(t, certs)
		})
		t.Run("DER: ok", func(t *testing.T) {
			serverStream.ctx = contextWithMD(certAsDER)

			certs, err := auth.authenticate(serverStream)

			assert.NoError(t, err)
			assert.Len(t, certs, 1)
		})
	})

}
