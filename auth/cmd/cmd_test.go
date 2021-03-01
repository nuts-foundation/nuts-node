package cmd

import (
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestFlagSet(t *testing.T) {
	flags := FlagSet()
	// Assert all start with module config key
	flags.VisitAll(func(flag *pflag.Flag) {
		assert.True(t, strings.HasPrefix(flag.Name, "auth."))
	})
}
