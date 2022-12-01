package nutstx

import (
	"crypto"
	"encoding/gob"
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
	ReadFrom(io.Reader) error
}

// AggregateSet holds all aggregates in use on the nutstx event-stream.
type AggregateSet struct {
	*SignatureAggregate
}

// NewAggregateSet is a constructor.
func NewAggregateSet() *AggregateSet {
	// not using field names ensures all are set
	return &AggregateSet{
		NewSignatureAggregate(),
	}
}

// List returns a new slice with each entry present once.
func (set *AggregateSet) List() []Aggregate {
	return []Aggregate{
		set.SignatureAggregate,
	}
}

// SignatureAggregate tracks the public keys in use.
type SignatureAggregate struct {
	perKeyID map[string]crypto.PublicKey
}

func NewSignatureAggregate() *SignatureAggregate {
	agg := SignatureAggregate{
		perKeyID: make(map[string]crypto.PublicKey),
	}
	gob.Register(agg.perKeyID)
	return &agg
}

// ApplyEvent implemens Aggregate.
func (agg *SignatureAggregate) ApplyEvent(e stream.Event, h jws.Headers) error {
	keyVal, ok := h.Get(jws.JWKKey)
	if !ok {
		return nil
	}
	key, ok := keyVal.(jwk.Key)
	if !ok {
		log.Printf(`nutstx: key drop: JWS %q parsed "jwk" to type %T, expected jwk.Key`, e.JWS, keyVal)
		return nil
	}

	// ensure new "kid"
	keyID := key.KeyID()
	if keyID == "" {
		log.Printf(`nutstx: key drop: JWS %q key without "kid"`, e.JWS)
		return nil
	}
	if _, ok = agg.perKeyID[keyID]; ok {
		log.Printf("nutstx: key drop: event %q key %q already present", e.SigPart(), keyID)
		return nil
	}

	// standard crypto.PublicKey extraction
	var raw any
	if err := key.Raw(&raw); err != nil {
		log.Printf("nutstx: key drop: JWS %q key extraction: %s", e.JWS, err)
		return nil
	}
	pub, ok := raw.(crypto.PublicKey)
	if !ok {
		log.Printf("nutstx: key drop: JWS %q key extracted as type %T—not a crypto.PublicKey", e.JWS, raw)
		return nil
	}

	agg.perKeyID[keyID] = pub
	return nil
}

// ReadFrom implements Aggregate.
func (agg *SignatureAggregate) ReadFrom(r io.Reader) error {
	for key := range agg.perKeyID {
		delete(agg.perKeyID, key)
	}
	return gob.NewDecoder(r).Decode(agg.perKeyID)
}

// WriteTo implements Aggregate.
func (agg *SignatureAggregate) WriteTo(w io.Writer) error {
	return gob.NewEncoder(w).Encode(agg.perKeyID)
}

// ByKeyIDOrNil returns the exact match for a JWK "kid".
func (agg *SignatureAggregate) ByKeyIDOrNil(kid string) crypto.PublicKey {
	return agg.perKeyID[kid]
}
