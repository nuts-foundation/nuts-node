package storage

import (
	"crypto"
	"fmt"
	"regexp"
)

// wrapper wraps a Storage backend and checks the validity of the kid on each of the relevant functions before
// forwarding the call to the wrapped backend.
type wrapper struct {
	kidPattern     *regexp.Regexp
	wrappedBackend Storage
}

// NewValidatedKIDBackendWrapper creates a new wrapper for storage backends.
// Every call to the backend which takes a kid as param, gets the kid validated against the provided kidPattern.
func NewValidatedKIDBackendWrapper(backend Storage, kidPattern *regexp.Regexp) Storage {
	return wrapper{
		kidPattern:     kidPattern,
		wrappedBackend: backend,
	}
}

func (w wrapper) validateKID(kid string) error {
	if !w.kidPattern.MatchString(kid) {
		return fmt.Errorf("invalid key ID: %s", kid)
	}
	return nil
}

func (w wrapper) GetPrivateKey(kid string) (crypto.Signer, error) {
	if err := w.validateKID(kid); err != nil {
		return nil, err
	}
	return w.wrappedBackend.GetPrivateKey(kid)
}

func (w wrapper) PrivateKeyExists(kid string) bool {
	if err := w.validateKID(kid); err != nil {
		return false
	}
	return w.wrappedBackend.PrivateKeyExists(kid)
}

func (w wrapper) SavePrivateKey(kid string, key crypto.PrivateKey) error {
	if err := w.validateKID(kid); err != nil {
		return err
	}
	return w.wrappedBackend.SavePrivateKey(kid, key)
}

func (w wrapper) ListPrivateKeys() []string {
	return w.wrappedBackend.ListPrivateKeys()
}
