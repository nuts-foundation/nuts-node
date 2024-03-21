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
	generateClientOptions()
	generateServerOptions(system)
	generateCLICommands(system)
}

func generateCLICommands(system *core.System) {
	const targetFile = "docs/pages/deployment/cli-reference.rst"
	writer, _ := os.OpenFile(targetFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)
	defer writer.Close()

	_, _ = writer.WriteString(".. _nuts-cli-reference:" + newline + newline)
	writeHeader(writer, "CLI Command Reference", 0)

	_, _ = writer.WriteString("There are 2 types of commands: server command and client commands. " +
		"Server commands (e.g. ``nuts server``) can only be run on the system where the node is (or will be) running, because they require the node's config. " +
		"Client commands are used to remotely administer a Nuts node and require the node's API address." + newline + newline)

	// Server commands
	writeHeader(writer, "Server Commands", 1)
	_, _ = writer.WriteString("The following options apply to the server commands below:" + newline + newline)

	_, _ = io.WriteString(writer, newline+"::"+newline+newline)
	writeCommandOptions(writer, cmd.CreateCommand(system).Commands()[0])

	err := GenerateCommandDocs(cmd.CreateCommand(system), writer, func(cmd *cobra.Command) bool {
		return serverCommands.contains(cmd.CommandPath()) && cmd.CommandPath() != "nuts"
	}, false)
	if err != nil {
		panic(err)
	}
	_, _ = io.WriteString(writer, newline)
}

func writeHeader(writer io.Writer, header string, level int) {
	c := []string{"#", "*", "^", "-"}[level]
	_, _ = writer.Write([]byte(header + newline))
	_, _ = writer.Write([]byte(strings.Repeat(c, len(header)) + newline + newline))
}

func generateClientOptions() {
	flags := make(map[string]*pflag.FlagSet)
	flags[""] = core.ClientConfigFlags()
	generatePartitionedConfigOptionsDocs("Client Options", "docs/pages/client_options.rst", flags)
}

func generateServerOptions(system *core.System) {
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
			return strings.HasPrefix(f.Name, "auth.")
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

	generatePartitionedConfigOptionsDocs("Server Options", "docs/pages/deployment/server_options.rst", filterFlags(flags, v5FlagsPredicates, true))
	generatePartitionedConfigOptionsDocs("did:nuts/gRPC Server Options", "docs/pages/deployment/server_options_didnuts.rst", filterFlags(flags, v5FlagsPredicates, false))
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

func generatePartitionedConfigOptionsDocs(tableName, fileName string, flags map[string]*pflag.FlagSet) {
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
	generateRstTable(tableName, fileName, values)
}

func flagsToSortedValues(flags *pflag.FlagSet) [][]rstValue {
	var l KeyList
	flags.VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		l = append(l, vals(f.Name, f.DefValue, f.Usage))
	})
	sort.Sort(l)
	return [][]rstValue(l)
}

func generateRstTable(tableName, fileName string, values [][]rstValue) {
	optionsFile, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)
	if err != nil {
		panic(err)
	}
	defer optionsFile.Close()
	optionsFile.WriteString(fmt.Sprintf(".. table:: %s\n", tableName))
	optionsFile.WriteString("    :widths: 20 30 50\n")
	optionsFile.WriteString("    :class: options-table\n\n")
	printRstTable(vals("Key", "Default", "Description"), values, optionsFile)
	if err := optionsFile.Sync(); err != nil {
		panic(err)
	}
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
