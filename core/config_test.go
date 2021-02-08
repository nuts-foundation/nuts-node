package core

import (
	"github.com/knadh/koanf"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_loadConfigIntoStruct(t *testing.T) {
	os.Setenv("NUTS_E", "nvironment")
	defer os.Unsetenv("NUTS_E")
	flagSet := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flagSet.String("f", "lag", "A great option")
	type Target struct {
		F string `koanf:"f"`
		E string `koanf:"e"`
	}
	var target Target
	err := loadConfigIntoStruct(flagSet, &target, koanf.New(defaultDelimiter))
	assert.NoError(t, err)
	assert.Equal(t, "lag", target.F)
	assert.Equal(t, "nvironment", target.E)
}
