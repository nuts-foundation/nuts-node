package pki

import (
	"crypto/tls"
	"github.com/nuts-foundation/nuts-node/core"
	pkiconfig "github.com/nuts-foundation/nuts-node/pki/config"
)

// CreateTLSConfig creates a tls.Config and Validator based on the given core.TLSConfig.
// The Validator still needs to be started before use.
func CreateTLSConfig(cfg core.TLSConfig) (Validator, *tls.Config, error) {
	clientCertificate, err := cfg.LoadCertificate()
	if err != nil {
		return nil, nil, err
	}
	trustStore, err := cfg.LoadTrustStore()
	if err != nil {
		return nil, nil, err
	}
	pkiCfg := pkiconfig.Config{
		MaxUpdateFailHours: 4,
	}
	validator, err := NewValidator(pkiCfg, trustStore.Certificates())
	if err != nil {
		return nil, nil, err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCertificate},
		RootCAs:      trustStore.CertPool,
		MinVersion:   core.MinTLSVersion,
	}
	if err = validator.SetValidatePeerCertificateFunc(tlsConfig); err != nil {
		return nil, nil, err
	}
	return validator, tlsConfig, nil
}
