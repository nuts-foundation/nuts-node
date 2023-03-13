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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func newAuthenticationInterceptor(clientCertHeaderName string) grpc.StreamServerInterceptor {
	return (&tlsOffloadingAuthenticator{clientCertHeaderName: clientCertHeaderName}).intercept
}

type tlsOffloadingAuthenticator struct {
	clientCertHeaderName string
}

func (t *tlsOffloadingAuthenticator) intercept(srv interface{}, serverStream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	certificates, err := t.authenticate(serverStream)
	if err != nil {
		log.Logger().
			WithError(err).
			Warnf("Unable to authenticate offloaded TLS")
		return status.Error(codes.Unauthenticated, "TLS client certificate authentication failed")
	}

	// Build TLS info and override in Peer info, which is set on the incoming context
	peerInfo, _ := peer.FromContext(serverStream.Context())
	if peerInfo == nil {
		peerInfo = &peer.Peer{}
	}
	peerInfo.AuthInfo = credentials.TLSInfo{
		State: tls.ConnectionState{
			PeerCertificates: certificates,
		},
		CommonAuthInfo: credentials.CommonAuthInfo{
			SecurityLevel: credentials.PrivacyAndIntegrity,
		},
	}
	ctx := peer.NewContext(serverStream.Context(), peerInfo)
	return handler(srv, &wrappedServerStream{ctx: ctx, ServerStream: serverStream})
}

func (t *tlsOffloadingAuthenticator) authenticate(serverStream grpc.ServerStream) ([]*x509.Certificate, error) {
	md, ok := metadata.FromIncomingContext(serverStream.Context())
	if !ok {
		return nil, errors.New("missing headers")
	}
	values := md.Get(t.clientCertHeaderName)
	if len(values) != 1 {
		return nil, fmt.Errorf("expected exactly 1 value for header '%s' (found %d)", t.clientCertHeaderName, len(values))
	}
	unescaped, err := url.QueryUnescape(values[0])
	if err != nil {
		return nil, errors.New("TLS client header escaping is invalid")
	}

	var certificates []*x509.Certificate
	if strings.Contains(unescaped, "-----BEGIN CERTIFICATE-----") {
		certificates, err = t.parsePEMCert(unescaped)
	} else {
		certificates, err = t.parseDERCert(values[0])
	}
	if err != nil {
		return nil, err
	}
	if len(certificates) != 1 {
		return nil, fmt.Errorf("expected exactly 1 client certificate in header, found %d", len(certificates))
	}
	return certificates, err
}

func (t *tlsOffloadingAuthenticator) parseDERCert(data string) ([]*x509.Certificate, error) {
	bytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("unable to base64 decode client cert header: %w", err)
	}
	certificate, err := x509.ParseCertificate(bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to DER decode client cert: %w", err)
	}
	return []*x509.Certificate{certificate}, nil
}

func (t *tlsOffloadingAuthenticator) parsePEMCert(data string) ([]*x509.Certificate, error) {
	certificates, err := core.ParseCertificates([]byte(data))
	if err != nil {
		return nil, fmt.Errorf("invalid client certificate(s) in header: %w", err)
	}
	return certificates, nil
}

type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the wrapper's ctx, overwriting the nested grpc.ServerStream.Context()
func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}
