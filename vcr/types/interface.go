package types

import (
	"github.com/nuts-foundation/go-did/vc"
	"time"
)

// Writer is the interface that groups al the VC write methods
type Writer interface {
	// StoreCredential writes a VC to storage. Before writing, it calls Verify!
	// It can handle duplicates.
	StoreCredential(vc vc.VerifiableCredential, validAt *time.Time) error
}
