package oidc4vci

import "sync"

func NewIssuerRegistry(issuerBaseURL string) *IssuerRegistry {
	// Add trailing slash if missing
	if issuerBaseURL[len(issuerBaseURL)-1] != '/' {
		issuerBaseURL += "/"
	}
	return &IssuerRegistry{
		issuerBaseURL: issuerBaseURL,
		issuers:       make(map[string]Issuer),
		mux:           &sync.Mutex{},
	}
}

// IssuerRegistry is a registry of Issuer instances, used to keep track of issuers in a multi-tenant environment.
type IssuerRegistry struct {
	issuerBaseURL string
	issuers       map[string]Issuer
	mux           *sync.Mutex
}

// Get returns the Issuer for the given issuing DID.
func (r *IssuerRegistry) Get(identifier string) Issuer {
	// TODO: Probably needs basic validation: do we support this identifier?
	r.mux.Lock()
	defer r.mux.Unlock()
	issuer, ok := r.issuers[identifier]
	if !ok {
		fullyQualifiedIdentifier := r.issuerBaseURL + identifier
		issuer = NewIssuer(fullyQualifiedIdentifier)
		r.issuers[identifier] = issuer
	}
	return issuer
}
