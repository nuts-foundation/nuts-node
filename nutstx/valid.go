package nutstx

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"

	"github.com/nuts-foundation/nuts-node/stream"
)

var (
	ErrKeyNotFound    = errors.New("nutstx: JWS signature key not found")
	ErrJWSAlg         = errors.New("nutstx: unsupported JWS algorithm")
	ErrJWSSig         = errors.New("nutstx: JWS signature mismatch")
	ErrJWSNoSigt      = errors.New("nutstx: JWS without numeric sign time")
	ErrJWSSigtNotNum  = errors.New("nutstx: JWS sign time not a number")
	ErrJWSSigtFuture  = errors.New("nutstx: JWS with sign time from the future")
	ErrJWSNoSig       = errors.New("nutstx: JWS without signatature")
	ErrJWSMultiSig    = errors.New("nutstx: JWS with multiple signatatures")
	ErrJWSNoKIDNoJWK  = errors.New("nutstx: JWS without KID nor JWK")
	ErrJWSKIDAndJWK   = errors.New("nutstx: JWS with both KID and JWK")
	ErrJWSNoCritSigt  = errors.New("nutstx: JWS without sigt in crit")
	ErrJWSNoCritVer   = errors.New("nutstx: JWS without ver in crit")
	ErrJWSNoCritPrevs = errors.New("nutstx: JWS without prevs in crit")
	ErrContentHash    = errors.New("nutstx: hash from JWS payload doesn't match transaction content")
)

// LiveSinceFunc abstracts the View method.
type LiveSinceFunc func(context.Context, time.Time) (*AggregateSet, time.Time, error)

// ValidEvent returns whether the event matches all constraint from Nuts RFC004.
func ValidEvent(ctx context.Context, e stream.Event, f LiveSinceFunc) error {
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

	// extract signatune time
	var signTime time.Time
	if v, ok := h.Get("sigt"); !ok {
		return ErrJWSNoSigt
	} else if n, ok := v.(float64); !ok {
		return ErrJWSSigtNotNum
	} else {
		signTime = numericTime(n)
		if time.Now().Before(signTime) {
			return ErrJWSSigtFuture
		}
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
		aggs, _, err := f(ctx, signTime)
		if err != nil {
			return err
		}
		key = aggs.SignatureAggregate.ByKeyIDOrNil(KID)
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
		if array, ok := crit.([]string); ok {
			for _, a := range array {
				switch a {
				case "sigt":
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

// NumericTime returns the Go mapping.
// Copied from github.com/pascaldekloe/jwt NumericTime.Time.
func numericTime(f float64) time.Time {
	var t time.Time
	switch {
	case f >= math.MaxInt64:
		t = time.Unix(math.MaxInt64, 0) // truncate
	case f <= math.MinInt64:
		t = time.Unix(math.MinInt64, 0) // truncate
	case f >= math.MaxInt64/1e9, f <= math.MinInt64/1e9:
		t = time.Unix(int64(math.Round(f)), 0)
	default:
		seconds, fraction := math.Modf(f)
		if fraction == 0 {
			// no rounding errors
			t = time.Unix(int64(seconds), 0)
		} else {
			t = time.Unix(0, int64(f*1e9))
		}
	}
	// NumericTime is without timezone
	return t.UTC()
}
