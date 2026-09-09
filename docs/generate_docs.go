/*
 * Copyright (C) 2021 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/nuts-foundation/nuts-node/cmd"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/spf13/pflag"
)

const newline = "\n"

type stringSlice []string

func (sl stringSlice) contains(s string) bool {
	for _, curr := range sl {
		if curr == s {
			return true
		}
	}
	return false
}

// serverCommands lists the commands that use the server config. The options server commands are only printed once, because the list is quite long.
var serverCommands stringSlice = []string{"nuts config", "nuts server", "nuts crypto fs2vault", "nuts crypto fs2external", "nuts http gen-token"}

func generateDocs() {
	system := cmd.CreateSystem(func() {})
	for fileName, content := range generatedDocFiles(system) {
		if err := os.WriteFile(fileName, content, os.ModePerm); err != nil {
			panic(err)
		}
	}
}

// generatedDocFiles renders all documentation files that are generated from the code, keyed by their (repo-relative)
// output path. generateDocs writes them to disk; the up-to-date test compares them against the committed files.
func generatedDocFiles(system *core.System) map[string][]byte {
	files := renderServerOptions(system)
	files["docs/pages/deployment/cli-reference.rst"] = renderCLICommands(system)
	return files
}

func renderCLICommands(system *core.System) []byte {
	writer := new(bytes.Buffer)
	_, _ = writer.WriteString(".. _nuts-cli-reference:" + newline + newline)
	writeHeader(writer, "Server CLI Command Reference", 0)

	_, _ = writer.WriteString("Aside from ``nuts server``, there are few other server commands that can be run. They can only be run on the system where the node is (or will be) running, because they require the node's config." + newline)
	_, _ = writer.WriteString("Refer to the configuration reference for how and what can be configured." + newline + newline)

	err := GenerateCommandDocs(cmd.CreateCommand(system), writer, func(cmd *cobra.Command) bool {
		return serverCommands.contains(cmd.CommandPath()) && cmd.CommandPath() != "nuts"
	}, false)
	if err != nil {
		panic(err)
	}
	_, _ = io.WriteString(writer, newline)
	return writer.Bytes()
}

func writeHeader(writer io.Writer, header string, level int) {
	c := []string{"#", "*", "^", "-"}[level]
	_, _ = writer.Write([]byte(header + newline))
	_, _ = writer.Write([]byte(strings.Repeat(c, len(header)) + newline + newline))
}

func renderServerOptions(system *core.System) map[string][]byte {
	flags := make(map[string]*pflag.FlagSet)
	// Resolve root command flags
	globalFlags := core.FlagSet()
	// Resolve server command flags
	serverCommand, _, _ := cmd.CreateCommand(system).Find([]string{"server"})
	globalFlags.AddFlagSet(serverCommand.Flags())
	// Now index the flags by engine
	flags[""] = globalFlags

	system.VisitEngines(func(engine core.Engine) {
		if m, ok := engine.(core.Injectable); ok {
			flagsForEngine, err := extractFlagsForEngine(globalFlags, m.Config(), strings.ToLower(m.Name()))
			if err != nil {
				panic(fmt.Sprintf("unable to generate server options for engine '%s': %s", m.Name(), err.Error()))
			}
			if flagsForEngine.HasAvailableFlags() {
				flags[m.Name()] = flagsForEngine
			}
		}
	})

	// We want 2 tables, one with all did:web-related and relevant core flags,
	// the rest (which is v5/did:nuts/gRPC-specific), goes into a second table below it.
	// The predicates below define which are v5-related and which are not.
	v5FlagsPredicates := []func(f *pflag.Flag) bool{
		func(f *pflag.Flag) bool {
			return strings.HasPrefix(f.Name, "events.")
		},
		func(f *pflag.Flag) bool {
			// Auth engine
			return strings.HasPrefix(f.Name, "auth.irma") ||
				strings.HasPrefix(f.Name, "auth.clockskew") ||
				strings.HasPrefix(f.Name, "auth.contractvalidators") ||
				strings.HasPrefix(f.Name, "auth.accesstokenlifespan")
		},
		func(f *pflag.Flag) bool {
			return strings.HasPrefix(f.Name, "tls.")
		},
		func(f *pflag.Flag) bool {
			return strings.HasPrefix(f.Name, "storage.redis.")
		},
		func(f *pflag.Flag) bool {
			return strings.HasPrefix(f.Name, "storage.bbolt.")
		},
		func(f *pflag.Flag) bool {
			return strings.HasPrefix(f.Name, "goldenhammer.")
		},
		func(f *pflag.Flag) bool {
			return strings.HasPrefix(f.Name, "network.")
		},
		func(f *pflag.Flag) bool {
			return strings.HasPrefix(f.Name, "vcr.openid4vci.")
		},
	}

	return map[string][]byte{
		"docs/pages/deployment/server_options.rst":         renderPartitionedConfigOptionsDocs("Server Options", filterFlags(flags, v5FlagsPredicates, true)),
		"docs/pages/deployment/server_options_didnuts.rst": renderPartitionedConfigOptionsDocs("did:nuts/gRPC Server Options", filterFlags(flags, v5FlagsPredicates, false)),
	}
}

func filterFlags(flags map[string]*pflag.FlagSet, predicates []func(f *pflag.Flag) bool, exclude bool) map[string]*pflag.FlagSet {
	result := make(map[string]*pflag.FlagSet)
	// If !exclude, only properties that match the predicate are included.
	// Otherwise, only properties that do not match the predicate are included.
	for engine, flagSet := range flags {
		result[engine] = pflag.NewFlagSet(engine, pflag.ContinueOnError)
		flagSet.VisitAll(func(f *pflag.Flag) {
			keep := exclude
			for _, predicate := range predicates {
				if predicate(f) {
					keep = !exclude
					break
				}
			}
			if keep {
				result[engine].AddFlag(f)
			}
		})
	}
	// Clean up resulting flags, if there are none for the engine, remove it
	for engine, flagSet := range result {
		if !flagSet.HasAvailableFlags() {
			delete(result, engine)
		}
	}
	return result
}

func extractFlagsForEngine(flagSet *pflag.FlagSet, config interface{}, engineName string) (*pflag.FlagSet, error) {
	result := pflag.FlagSet{}
	structType := reflect.TypeOf(config).Elem()

	if structType.Kind() != reflect.Struct {
		return nil, errors.New("config has not the type struct (perhaps it's a pointer?)")
	}

	flagSet.VisitAll(func(current *pflag.Flag) {
		println(current.Name, engineName)
		if current.Name == engineName ||
			strings.HasPrefix(current.Name, engineName+".") {
			// This flag belongs to this engine, so copy it and hide it in the input flag set
			flagCopy := *current
			current.Hidden = true
			result.AddFlag(&flagCopy)

			return
		}
	})

	return &result, nil
}

func renderPartitionedConfigOptionsDocs(tableName string, flags map[string]*pflag.FlagSet) []byte {
	var keys []string
	for key := range flags {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	values := make([][]rstValue, 0)
	for _, key := range keys {
		if key != "" {
			values = append(values, []rstValue{{
				value: key,
				bold:  true,
			}})
		}
		values = append(values, flagsToSortedValues(flags[key])...)
	}
	return renderRstTable(tableName, values)
}

func flagsToSortedValues(flags *pflag.FlagSet) [][]rstValue {
	var l KeyList
	flags.VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		defValue := normalizeDefaultValue(f)
		l = append(l, vals(f.Name, defValue, f.Usage))
	})
	sort.Sort(l)
	return l
}

func normalizeDefaultValue(f *pflag.Flag) string {
	// maps (stringToString) are randomly ordered, so we need to sort them to have consistent output.
	// Otherwise, everytime the documentation is generated order might change, causing unnecessary diffs.
	// They are in the form of [key1=value1,key2=value2]
	defValue := f.DefValue
	if f.Value.Type() == "stringToString" {
		value := f.Value.String()
		value = strings.TrimPrefix(value, "[")
		value = strings.TrimSuffix(value, "]")
		values := strings.Split(value, ",")
		sort.Strings(values)
		defValue = fmt.Sprintf("[%s]", strings.Join(values, ","))
	}
	return defValue
}

func renderRstTable(tableName string, values [][]rstValue) []byte {
	buffer := new(bytes.Buffer)
	fmt.Fprintf(buffer, ".. table:: %s\n", tableName)
	buffer.WriteString("    :widths: 20 30 50\n")
	buffer.WriteString("    :class: options-table\n\n")
	printRstTable(vals("Key", "Default", "Description"), values, buffer)
	return buffer.Bytes()
}

// KeyList sorts keys alphabetically, with any nested content at the end.
type KeyList [][]rstValue

// Len implements sort.Interface.
func (l KeyList) Len() int { return len(l) }

// Swap implements sort.Interface.
func (l KeyList) Swap(i, j int) { l[i], l[j] = l[j], l[i] }

// Less implements sort.Interface.
func (l KeyList) Less(i, j int) bool {
	a := strings.Split(l[i][0].value, ".")
	b := strings.Split(l[j][0].value, ".")

	for i := range a {
		switch {
		case a[i] == b[i]:
			continue
		case len(a)-i == 1 && len(b)-i != 1:
			return true // j is a subgroup of i
		case len(a)-i != 1 && len(b)-i == 1:
			return false // i is a subgroup of j
		default:
			return a[i] < b[i]
		}
	}

	return false // equal actually
}
