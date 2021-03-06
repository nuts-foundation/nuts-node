package main

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/nuts-foundation/nuts-node/cmd"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/spf13/pflag"
)

func main() {
	system := cmd.CreateSystem()
	generateClientOptions(system)
	generateServerOptions(system)
}

func generateClientOptions(system *core.System) {
	flags := make(map[string]*pflag.FlagSet)
	flags[""] = core.ClientConfigFlags()
	generatePartitionedConfigOptionsDocs("docs/pages/client_options.rst", flags)
}

func generateServerOptions(system *core.System) {
	flags := make(map[string]*pflag.FlagSet)
	// Resolve root command flags
	globalFlags := core.FlagSet()
	// Resolve server command flags
	serverCommand, _, _ := cmd.CreateCommand(system).Find([]string{"server"})
	globalFlags.AddFlagSet(serverCommand.PersistentFlags())
	// Now index the flags by engine
	flags[""] = globalFlags

	system.VisitEngines(func(engine core.Engine) {
		if m, ok := engine.(core.Injectable); ok {
			flagsForEngine := extractFlagsForEngine(globalFlags, m.Config())
			if flagsForEngine.HasAvailableFlags() {
				flags[m.Name()] = flagsForEngine
			}
		}
	})

	generatePartitionedConfigOptionsDocs("docs/pages/configuration/server_options.rst", flags)
}

func extractFlagsForEngine(flagSet *pflag.FlagSet, config interface{}) *pflag.FlagSet {
	result := pflag.FlagSet{}
	flagNames := []string{}
	structType := reflect.TypeOf(config).Elem()

	for i := 0; i < structType.NumField(); i++ {
		fieldType := structType.Field(i)

		tag, ok := fieldType.Tag.Lookup("koanf")
		if !ok {
			continue
		}

		flagNames = append(flagNames, tag)
	}

	flagSet.VisitAll(func(current *pflag.Flag) {
		for _, flagName := range flagNames {
			if current.Name == flagName ||
				strings.HasPrefix(current.Name, fmt.Sprintf("%s.", flagName)) {
				// This flag belongs to this engine, so copy it and hide it in the input flag set
				flagCopy := *current
				current.Hidden = true
				result.AddFlag(&flagCopy)

				return
			}
		}
	})

	return &result
}

func generatePartitionedConfigOptionsDocs(fileName string, flags map[string]*pflag.FlagSet) {
	sortedKeys := make([]string, 0)
	for key := range flags {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)

	values := make([][]rstValue, 0)
	for _, key := range sortedKeys {
		if key != "" {
			values = append(values, []rstValue{{
				value: key,
				bold:  true,
			}})
		}
		values = append(values, flagsToSortedValues(flags[key])...)
	}
	generateRstTable(fileName, values)
}

func flagsToSortedValues(flags *pflag.FlagSet) [][]rstValue {
	values := make([][]rstValue, 0)
	flags.VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		values = append(values, vals(f.Name, f.DefValue, f.Usage))
	})
	// We want global properties (the ones without dots) to appear at the top, so we need some custom sorting
	sort.Slice(values, func(i, j int) bool {
		s1 := values[i][0].value
		s2 := values[j][0].value
		if strings.Contains(s1, ".") {
			if strings.Contains(s2, ".") {
				return s1 < s2
			}
			return false
		} else {
			if strings.Contains(s2, ".") {
				return true
			}
			return s1 < s2
		}
	})
	return values
}

func generateRstTable(fileName string, values [][]rstValue) {
	optionsFile, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)
	if err != nil {
		panic(err)
	}
	defer optionsFile.Close()
	printRstTable(vals("Key", "Default", "Description"), values, optionsFile)
	if err := optionsFile.Sync(); err != nil {
		panic(err)
	}
}
