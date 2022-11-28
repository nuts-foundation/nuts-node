package nutstx

import (
	"crypto"
	"io"
	"log"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-node/stream"
)

// Aggregate collects state from an event stream.
type Aggregate interface {
	// ApplyEvent adds the next in line.
	// All errors are fatal to the aggregate.
	ApplyEvent(stream.Event, jws.Headers) error

	// WriteTo dumps a snapshot of the state.
	WriteTo(io.Writer) error

	// ReadFrom replaces the current state from a WriteTo.
	ReadeFrom(io.Reader) error
}

// SignatureAggregate tracks the public keys in use.
type SignatureAggregate struct {
	perKeyID map[string]crypto.PublicKey
}

// ApplyEvent implemens Aggregate.
func (agg *SignatureAggregate) ApplyEvent(e stream.Event, h jws.Headers) {
	keyVal, ok := h.Get(jws.JWKKey)
	if !ok {
		return
	}
	key, ok := keyVal.(jwk.Key)
	if !ok {
		log.Printf(`nutstx: key drop: JWS %q parsed "jwk" to type %T, expected jwk.Key`, e.JWS, keyVal)
		return
	}

	// ensure new "kid"
	keyID := key.KeyID()
	if keyID == "" {
		log.Printf(`nutstx: key drop: JWS %q key without "kid"`, e.JWS)
		return
	}
	if _, ok = agg.perKeyID[keyID]; ok {
		log.Printf("nutstx: key drop: event %q key %q already present", e.SigPart(), keyID)
		return
	}

	// standard crypto.PublicKey extraction
	var raw any
	if err := key.Raw(&raw); err != nil {
		log.Printf("nutstx: key drop: JWS %q key extraction: %s", e.JWS, err)
		return
	}
	pub, ok := raw.(crypto.PublicKey)
	if !ok {
		log.Printf("nutstx: key drop: JWS %q key extracted as type %T—not a crypto.PublicKey", e.JWS, raw)
		return
	}

	if agg.perKeyID == nil {
		agg.perKeyID = make(map[string]crypto.PublicKey)
	}
	agg.perKeyID[keyID] = pub
}

// ByKeyIDOrNil returns the exact match for a JWK "kid".
func (agg *SignatureAggregate) ByKeyIDOrNil(kid string) crypto.PublicKey {
	return agg.perKeyID[kid]
}
