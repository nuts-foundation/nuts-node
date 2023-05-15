package pki

import (
	"github.com/nuts-foundation/nuts-node/pki/config"
	"github.com/spf13/pflag"
)

// FlagSet contains flags relevant for JSON-LD
func FlagSet() *pflag.FlagSet {
	defs := config.DefaultConfig()

	flagSet := pflag.NewFlagSet("pki", pflag.ContinueOnError)

	// Flags for denylist features
	flagSet.Int("pki.maxupdatefailhours", defs.MaxUpdateFailHours, "maximum number of hours that a denylist update can fail")
	flagSet.Bool("pki.softfail", defs.Softfail, "do not reject certificates if their revocation status cannot be established")
	// TODO: Choose a default trusted signer key
	flagSet.String("pki.denylist.trustedsigner", defs.Denylist.TrustedSigner, "Ed25519 public key (in PEM format) of the trusted signer for denylists")
	// TODO: Choose a default denylist URL
	flagSet.String("pki.denylist.url", defs.Denylist.URL, "URL of PKI denylist (set to empty string to disable)")

	// Changing these config values is not recommended, and they are expected to almost always be the same value, so
	// do not show them in the config dump
	flagSet.MarkHidden("pki.denylist.trustedsigner")
	flagSet.MarkHidden("pki.denylist.url")
	return flagSet
}
