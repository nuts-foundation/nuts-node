package core

import (
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/spf13/pflag"
	"os"
	"strings"
)

const defaultPrefix = "NUTS_"
const defaultDelimiter = "."

func loadConfigIntoStruct(flags *pflag.FlagSet, target interface{}, configMap *koanf.Koanf) error {
	// load env
	e := env.Provider(defaultPrefix, defaultDelimiter, func(s string) string {
		return strings.Replace(strings.ToLower(
			strings.TrimPrefix(s, defaultPrefix)), "_", defaultDelimiter, -1)
	})
	// errors can't occur for this provider
	_ = configMap.Load(e, nil)

	// load cmd params
	if len(os.Args) > 1 {
		_ = flags.Parse(os.Args[1:])
	}
	// errors can't occur for this provider
	_ = configMap.Load(posflag.Provider(flags, defaultDelimiter, configMap), nil)

	// load into struct
	return configMap.Unmarshal("", target)
}
