package didman

import "github.com/nuts-foundation/go-did"

// Bolt defines functions for enabling/disabling a bolt for a specific care provider.
type Bolt interface {

	// Enable enables the Bolt for the given care provider.
	Enable(careProvider did.DID, properties map[string]string) error

	// Disable disables the Bolt for the given care provider.
	Disable(careProvider did.DID) error
}
