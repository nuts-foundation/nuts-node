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
	"context"
	"crypto/tls"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"time"
)

const (
	moduleName = "PKI"

	// health check names
	healthCRL      = "crl"
	healthDenylist = "denylist"
)

var _ Validator = (*PKI)(nil)
var _ Provider = (*PKI)(nil)

type PKI struct {
	*validator
	ctx      context.Context
	shutdown context.CancelFunc
	config   Config
}

func New() *PKI {
	return &PKI{config: DefaultConfig()}
}

func (p *PKI) Name() string {
	return moduleName
}

func (p *PKI) Config() any {
	return &p.config
}

func (p *PKI) Configure(_ core.ServerConfig) error {
	var err error
	p.validator, err = newValidator(p.config)
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

// CreateTLSConfig creates a tls.Config based on the given core.TLSConfig for outbound and inbound connections to other Nuts nodes.
// It registers the CA certificates in the trust store in the validator which will start fetching their CRLs.
// It finally registers a VerifyPeerCertificateFunc in the tls.Config which will validate the peer certificate against the validator.
// If TLS is not enabled, it returns nil (and no error).
func (p *PKI) CreateTLSConfig(cfg core.TLSConfig) (*tls.Config, error) {
	tlsConfig, err := cfg.Load()
	if err != nil {
		return nil, err
	}
	if tlsConfig == nil {
		// TLS is not enabled
		return nil, nil
	}
	_ = p.SetVerifyPeerCertificateFunc(tlsConfig) // no error can occur
	return tlsConfig, nil
}

type outdatedCRL struct {
	Issuer      string
	Endpoint    string
	LastUpdated time.Time
}

func (p *PKI) CheckHealth() map[string]core.Health {
	results := make(map[string]core.Health, 1)
	maxDelay := time.Duration(p.maxUpdateFailHours) * time.Hour

	// deny list
	if p.denylist != nil && p.denylist.URL() != "" && isOutdated(p.denylist.LastUpdated(), maxDelay) {
		// deny list is only added when it is outdated
		results[healthDenylist] = core.Health{
			Status: core.HealthStatusDown,
			Details: outdatedCRL{
				Issuer:      "denylist",
				Endpoint:    p.denylist.URL(),
				LastUpdated: p.denylist.LastUpdated(),
			},
		}
	}

	// CRLs
	var outdatedList []outdatedCRL
	p.validator.crls.Range(func(endpointAny, crlAny any) bool {
		// Convert the untyped variables
		endpoint, isString := endpointAny.(string)
		crl, isCRL := crlAny.(*revocationList)

		// Ensure the type converions succeeded
		if !isString || !isCRL {
			// This should never happen. If it does, it indicates a programming error in which
			// the v.crls sync.Map has been incorrectly populated.
			logger().
				WithField("endpoint", fmt.Sprintf("%v", endpointAny)).
				WithField("CRL", fmt.Sprintf("%v", crlAny)).
				Error("CRL validator is invalid")

			// Return true in order to continue the range operation
			return true
		}

		// Add clrs to list if they have not beer updated within the configure interval
		// TODO: should this also return unhealthy on outdated certificates in the truststore?
		if !invalidByTime(crl.issuer) && isOutdated(crl.lastUpdated, maxDelay) {
			outdatedList = append(outdatedList, outdatedCRL{
				Issuer:      crl.issuer.Subject.String(),
				Endpoint:    endpoint,
				LastUpdated: crl.lastUpdated,
			})
		}
		return true
	})

	// set CRL health status
	if len(outdatedList) == 0 {
		results[healthCRL] = core.Health{
			Status: core.HealthStatusUp,
		}
	} else {
		results[healthCRL] = core.Health{
			Status:  core.HealthStatusDown,
			Details: outdatedList,
		}
	}

	return results
}
