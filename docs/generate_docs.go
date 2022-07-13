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
	"github.com/spf13/cobra/doc"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/nuts-foundation/nuts-node/cmd"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/spf13/pflag"
)

func generateDocs() {
	system := cmd.CreateSystem()
	generateClientOptions()
	generateServerOptions(system)
	generateCLICommands(system)
}

func generateCLICommands(system *core.System) {
	cliDirectory := "docs/pages/deployment/cli"
	cmdsDirectory := path.Join(cliDirectory, "commands")
	// Clean up first
	for _, fileName := range listDirectory(cmdsDirectory) {
		_ = os.Remove(filepath.Join(cmdsDirectory, fileName))
	}
	// Generate; see https://chromium.googlesource.com/external/github.com/spf13/cobra/+/HEAD/doc/rest_docs.md
	linkHandler := func(name, ref string) string {
		return fmt.Sprintf(":ref:`%s <%s>`", name, ref)
	}
	prepender := func(s string) string { return "" }
	err := doc.GenReSTTreeCustom(cmd.CreateCommand(system), cmdsDirectory, prepender, linkHandler)
	if err != nil {
		panic(err)
	}
	// Generate index.rst
	const base = `.. _nuts-cli-command-reference:

Nuts CLI Command Reference
**************************

`
	indexFile, err := os.OpenFile(path.Join(cliDirectory, "index.rst"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)
	defer indexFile.Close()
	_, _ = indexFile.WriteString(base)
	for _, fileName := range listDirectory(cmdsDirectory) {
		part := fmt.Sprintf(".. include:: commands/%s\n", fileName)
		_, _ = indexFile.WriteString(part)
		_, _ = indexFile.WriteString("\n\n------------\n\n")

		// Rewrite command usage
		// - Rewrite subsections to bold text
		const removeStarting = "SEE ALSO"
		const sectionToRemove = `
Options inherited from parent commands
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::
`
		absolutePath := path.Join(cmdsDirectory, fileName)
		cmdHelpBytes, _ := os.ReadFile(absolutePath)
		cmdHelp := string(cmdHelpBytes)

		// Remove caption "Options inherited from parent commands"
		cmdHelp = strings.ReplaceAll(cmdHelp, sectionToRemove, "")
		// Remove See Also
		seeAlsoIndex := strings.Index(cmdHelp, removeStarting)
		cmdHelp = cmdHelp[:seeAlsoIndex]
		cmdHelp = strings.TrimSpace(cmdHelp)
		// Rewrite subcaptions to bolded text
		cmdHelp = strings.ReplaceAll(cmdHelp, "Synopsis\n~~~~~~~~\n", "**Synopsis**")
		cmdHelp = strings.ReplaceAll(cmdHelp, "Options\n~~~~~~~\n", "**Options**")

		_ = os.WriteFile(absolutePath, []byte(cmdHelp), os.ModeType)
	}
}

func generateClientOptions() {
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
	globalFlags.AddFlagSet(serverCommand.Flags())
	// Now index the flags by engine
	flags[""] = globalFlags

	system.VisitEngines(func(engine core.Engine) {
		if m, ok := engine.(core.Injectable); ok {
			flagsForEngine, err := extractFlagsForEngine(globalFlags, m.Config())
			if err != nil {
				panic(fmt.Sprintf("unable to generate server options for engine '%s': %s", m.Name(), err.Error()))
			}
			if flagsForEngine.HasAvailableFlags() {
				flags[m.Name()] = flagsForEngine
			}
		}
	})

	generatePartitionedConfigOptionsDocs("docs/pages/deployment/server_options.rst", flags)
}

func extractFlagsForEngine(flagSet *pflag.FlagSet, config interface{}) (*pflag.FlagSet, error) {
	result := pflag.FlagSet{}
	flagNames := []string{}
	structType := reflect.TypeOf(config).Elem()

	if structType.Kind() != reflect.Struct {
		return nil, errors.New("config has not the type struct (perhaps it's a pointer?)")
	}

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

	return &result, nil
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

func listDirectory(targetDirectory string) []string {
	d, _ := os.Open(targetDirectory)
	defer d.Close()
	names, _ := d.Readdirnames(-1)
	sort.Strings(names)
	return names
}
