package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"net/url"
)

type tlsOffloadingAuthenticator struct {
	clientCertHeaderName string
}

func (t *tlsOffloadingAuthenticator) Intercept(srv interface{}, serverStream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	certificates, err := t.authenticate(serverStream)
	if err != nil {
		log.Logger().Warnf("Unable to authenticate offloaded TLS: %s", err)
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
	certificates, err := core.ParseCertificates([]byte(unescaped))
	if err != nil {
		return nil, fmt.Errorf("invalid client certificate(s) in header: %w", err)
	}
	if len(certificates) != 1 {
		return nil, fmt.Errorf("expected exactly 1 client certificate in header, found %d", len(certificates))
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
