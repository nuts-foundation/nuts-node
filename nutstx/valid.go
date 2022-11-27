package nutstx

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"

	"github.com/nuts-foundation/nuts-node/stream"
)

var (
	ErrKeyNotFound    = errors.New("nutstx: JWS signature key not found")
	ErrJWSAlg         = errors.New("nutstx: unsupported JWS algorithm")
	ErrJWSSig         = errors.New("nutstx: JWS signature mismatch")
	ErrJWSNoSig       = errors.New("nutstx: JWS without signatature")
	ErrJWSMultiSig    = errors.New("nutstx: JWS with multiple signatatures")
	ErrJWSNoKIDNoJWK  = errors.New("nutstx: JWS without KID nor JWK")
	ErrJWSKIDAndJWK   = errors.New("nutstx: JWS with both KID and JWK")
	ErrJWSNoCritSigt  = errors.New("nutstx: JWS without sigt in crit")
	ErrJWSNoCritVer   = errors.New("nutstx: JWS without ver in crit")
	ErrJWSNoCritPrevs = errors.New("nutstx: JWS without prevs in crit")
	ErrContentHash    = errors.New("hash from JWS payload doesn't match Nuts transaction content")
)

// ValidEvent returns whether the event matches all constraint from Nuts RFC004.
func ValidEvent(e stream.Event, byKeyIDOrNil func(string) crypto.PublicKey) error {
	msg, err := jws.ParseString(e.JWS)
	if err != nil {
		return fmt.Errorf("nutstx: malformed JWS: %w", err)
	}

	var h jws.Headers
	switch sigs := msg.Signatures(); len(sigs) {
	case 0:
		return ErrJWSNoSig
	case 1:
		h = sigs[0].ProtectedHeaders()
	default:
		return ErrJWSMultiSig
	}

	var key crypto.PublicKey
	// “The signing key is indicated by kid or jwk. One of them MUST be
	// present, but not both.”
	// — Nuts RFC004
	switch KID, JWK := h.KeyID(), h.JWK(); {
	case KID != "" && JWK != nil:
		return ErrJWSKIDAndJWK
	default:
		return ErrJWSNoKIDNoJWK
	case KID != "":
		key = byKeyIDOrNil(KID)
		if key == nil {
			return ErrKeyNotFound
		}
	case JWK != nil:
		var err error
		key, err = JWK.PublicKey()
		if err != nil {
			return fmt.Errorf("nutstx: malformed JWK in JWS: %w", err)
		}
	}

	switch alg := h.Algorithm(); alg {
	default:
		return ErrJWSAlg
	case jwa.ES256, jwa.ES384, jwa.ES512, jwa.PS256, jwa.PS384, jwa.PS512:
		_, err := jws.Verify([]byte(e.JWS), jwa.SignatureAlgorithm(alg), key)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrJWSSig, err)
		}
	}

	var critSigt, critVer, critPrevs bool
	if crit, ok := h.Get("crit"); ok {
		if array, ok := crit.([]any); ok {
			for _, a := range array {
				switch a {
				case "crit":
					critSigt = true
				case "ver":
					critVer = true
				case "prevs":
					critPrevs = true
				}
			}
		}
	}
	switch {
	case !critSigt:
		return ErrJWSNoCritSigt
	case !critVer:
		return ErrJWSNoCritVer
	case !critPrevs:
		return ErrJWSNoCritPrevs
	}

	var payloadHash, contentHash [sha256.Size]byte
	_, err = hex.Decode(payloadHash[:], msg.Payload())
	if err != nil {
		return fmt.Errorf("nutstx: malformed JWS payload [content hash]: %w", err)
	}
	digest := sha256.New()
	digest.Write(e.Content)
	digest.Sum(contentHash[:0])
	if payloadHash != contentHash {
		return ErrContentHash
	}

	return nil
}
