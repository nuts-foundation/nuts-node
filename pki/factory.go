/*
 * Copyright (C) 2023 Nuts community
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

package pki

import (
	"crypto/tls"
	"github.com/nuts-foundation/nuts-node/core"
	pkiconfig "github.com/nuts-foundation/nuts-node/pki/config"
)

// CreateClientTLSConfig creates a tls.Config and Validator based on the given core.TLSConfig for outbound connections to other Nuts nodes.
// The Validator still needs to be started before use.
func CreateClientTLSConfig(cfg core.TLSConfig) (Validator, *tls.Config, error) {
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
