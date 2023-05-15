package pki

import (
	"context"
	"crypto/tls"
	"crypto/x509"

	"github.com/nuts-foundation/nuts-node/core"
	pkiconfig "github.com/nuts-foundation/nuts-node/pki/config"
)

const moduleName = "PKI"

var _ Validator = (*PKI)(nil)

type Validator interface {

	// Validate returns an error if any of the certificates in the chain has been revoked, or if the request cannot be processed.
	// ErrCertRevoked and ErrCertUntrusted indicate that at least one of the certificates is revoked, or signed by a CA that is not in the truststore.
	// ErrCRLMissing and ErrCRLExpired signal that at least one of the certificates cannot be validated reliably.
	// If the certificate was revoked on an expired CRL, it wil return ErrCertRevoked. Ignoring ErrCRLMissing and ErrCRLExpired changes the behavior from hard-fail to soft-fail.
	// The certificate chain is expected to be sorted leaf to root.
	// Calling Validate before Start results in an error.
	Validate(chain []*x509.Certificate) error

	// SetValidatePeerCertificateFunc sets config.ValidatePeerCertificate to use Validate.
	// Returns an error when config.Certificates contain certificates that cannot be parsed,
	// or are signed by CAs that are not in the Validator's truststore.
	SetValidatePeerCertificateFunc(config *tls.Config) error

	AddCerts(cert []*x509.Certificate) error
}

type PKI struct {
	*validator
	ctx      context.Context
	shutdown context.CancelFunc
	config   pkiconfig.Config
}

func New() *PKI {
	return &PKI{config: pkiconfig.DefaultConfig()}
}

func (p *PKI) Name() string {
	return moduleName
}

func (p *PKI) Config() any {
	return &p.config
}

func (p *PKI) Configure(config core.ServerConfig) error {
	truststore, err := config.TLS.LoadTrustStore()
	if err != nil {
		return err
	}

	//certificate, err := config.TLS.LoadCertificate()
	//if err != nil {
	//	return err
	//}

	p.validator, err = newValidator(p.config, truststore.Certificates())
	if err != nil {
		return err
	}

	return nil
}

func (p *PKI) Start() error {
	p.ctx, p.shutdown = context.WithCancel(context.Background())
	p.validator.start(p.ctx)
	return nil
}

func (p *PKI) Shutdown() error {
	p.shutdown()

	return nil
}

func (p *PKI) AddCerts(certs []*x509.Certificate) error {
	// TODO: seed expected CAs so they do not have to be downloaded when first encountered
	// Do not store the certs, just optimistically add CRL endpoints

	for _, cert := range certs {
		if err := p.validator.addEndpoints(cert, cert.CRLDistributionPoints); err != nil {
			return err
		}
	}
	return nil
}
