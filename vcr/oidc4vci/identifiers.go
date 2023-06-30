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

package oidc4vci

import (
	"crypto/tls"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

// IdentifierResolver defines the interface for resolving OpenID4VCI identifiers (of wallet and issuer).
// The identifier is the base URL of the issuer or wallet, at which well-known endpoints can be found.
type IdentifierResolver interface {
	Resolve(id did.DID) (string, error)
}

var _ IdentifierResolver = DIDIdentifierResolver{}

// DIDIdentifierResolver is a IdentifierResolver that resolves identifiers from DID documents.
type DIDIdentifierResolver struct {
	ServiceResolver didservice.ServiceResolver
}

func (i DIDIdentifierResolver) Resolve(id did.DID) (string, error) {
	service, err := i.ServiceResolver.Resolve(didservice.MakeServiceReference(id, types.BaseURLServiceType), didservice.DefaultMaxServiceReferenceDepth)
	if didservice.IsFunctionalResolveError(err) {
		return "", nil
	} else if err != nil {
		return "", fmt.Errorf("unable to resolve %s service: %w", types.BaseURLServiceType, err)
	}
	var result string
	_ = service.UnmarshalServiceEndpoint(&result)
	if result != "" {
		result = core.JoinURLPaths(result, "n2n", "identity", url.PathEscape(id.String()))
	}
	return result, nil
}

// NewTLSIdentifierResolver creates a IdentifierResolver that tries to derive the identifier from the TLS certificate if it can't be resolved using the DID document.
// It does so by constructing the identifier from the CommonName and SubjectAlternativeNames of the certificate and requesting metadata.
func NewTLSIdentifierResolver(underlying IdentifierResolver, config *tls.Config) IdentifierResolver {
	result := tlsIdentifierResolver{
		underlying:       underlying,
		config:           config,
		cachedIdentifier: new(atomic.Pointer[string]),
		lastAttempt:      new(atomic.Pointer[time.Time]),
	}
	result.lastAttempt.Store(new(time.Time))
	return result
}

const tlsAttemptInterval = time.Minute

var tlsIdentifierResolverPort = 443

var _ IdentifierResolver = tlsIdentifierResolver{}

type tlsIdentifierResolver struct {
	underlying       IdentifierResolver
	config           *tls.Config
	cachedIdentifier *atomic.Pointer[string]
	// lastAttempt is the time at which the last attempt to resolve the identifier from the TLS certificate was made.
	// It is used to prevent spamming the local node, since it could be called on each OpenID4VCI request.
	lastAttempt *atomic.Pointer[time.Time]
}

func (t tlsIdentifierResolver) Resolve(id did.DID) (string, error) {
	cached := t.cachedIdentifier.Load()
	if cached != nil {
		return *cached, nil
	}

	identifier, err := t.underlying.Resolve(id)
	if err != nil {
		return "", err
	}
	if identifier != "" {
		return identifier, nil
	}

	// Could not load from DID document, try to derive from TLS certificate
	if time.Since(*t.lastAttempt.Load()) > tlsAttemptInterval {
		lastAttempt := time.Now()
		t.lastAttempt.Store(&lastAttempt)
		identifier, err = t.resolveFromCertificate(id)
		if err == nil {
			t.cachedIdentifier.Store(&identifier)
		}
		return identifier, err
	}
	return "", nil
}

func (t tlsIdentifierResolver) resolveFromCertificate(id did.DID) (string, error) {
	// Construct candidate URLs from TLS certificate SANs
	var candidateURLs []string
	// Support legacy TLS certificates with host name in Subject.CommonName as well
	candidateHosts := append(t.config.Certificates[0].Leaf.DNSNames, t.config.Certificates[0].Leaf.Subject.CommonName)
	for _, host := range candidateHosts {
		candidateURLs = append(candidateURLs, fmt.Sprintf("https://%s:%d", host, tlsIdentifierResolverPort))
	}

	// Resolve URLs
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.TLSClientConfig = t.config
	httpClient := &http.Client{
		Timeout:   5 * time.Second,
		Transport: httpTransport,
	}
	for _, candidateURL := range candidateURLs {
		issuerIdentifier := core.JoinURLPaths(candidateURL, "n2n", "identity", url.PathEscape(id.String()))
		err := t.testIdentifier(issuerIdentifier, httpClient)
		if err != nil {
			log.Logger().WithError(err).Debugf("Attempted node DID services base URL, but didn't work: %s", candidateURL)
			continue
		}
		return issuerIdentifier, nil
	}
	return "", nil
}

func (t tlsIdentifierResolver) testIdentifier(issuerIdentifier string, httpClient *http.Client) error {
	metadataURL := core.JoinURLPaths(issuerIdentifier, CredentialIssuerMetadataWellKnownPath)
	httpResponse, err := httpClient.Head(metadataURL)
	if err != nil {
		return err
	}
	if httpResponse.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d", httpResponse.StatusCode)
	}
	contentType := httpResponse.Header.Get("Content-Type")
	if contentType != "application/json" {
		return fmt.Errorf("unexpected content type %s", contentType)
	}
	return nil
}
