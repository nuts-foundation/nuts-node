package cmd

import (
	"sort"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestFlagSet(t *testing.T) {
	flags := FlagSet()

	var keys []string

	// Assert all start with module config key
	flags.VisitAll(func(flag *pflag.Flag) {
		keys = append(keys, flag.Name)
	})

	sort.Strings(keys)

	assert.Equal(t, []string{
		ConfEventsHostname,
		ConfEventsPort,
		ConfEventsStorageDir,
	}, keys)
}
