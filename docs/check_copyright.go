package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var yearRegex = regexp.MustCompilePOSIX("Copyright \\(C\\) ([0-9]{4})(\\.?) Nuts community")

var yearRegexReplacement = fmt.Sprintf("Copyright (C) %d Nuts community", time.Now().Year())

var copyrightText = fmt.Sprintf(`/*
 * %s
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

`, yearRegexReplacement)

func fixCopyright() {
	dir := "./"
	// Assert we're in the right directory
	if _, err := os.Stat(path.Join(dir, ".gitignore")); err != nil {
		panic("incorrect directory")
	}

	err := filepath.Walk(dir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(info.Name(), ".go") {
				// only Go files
				return nil
			}
			if strings.Contains(info.Name(), "mock") {
				return nil
			}

			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			dataStr := string(data)
			if strings.Contains(dataStr, "DO NOT EDIT") {
				// Generated code
				return nil
			}

			// Looking for "Copyright (C) (year) Nuts community"
			if strings.Contains(dataStr, "Copyright (C)") && strings.Contains(dataStr, "Nuts community") {
				// See if we have to adjust the year
				dataWithYear := string(yearRegex.ReplaceAll(data, []byte(yearRegexReplacement)))
				if dataWithYear == dataStr {
					// Up-to-date
					return nil
				}
				dataStr = dataWithYear
			} else {
				dataStr = copyrightText + dataStr
			}
			println("Fixing copyright notice on", path)
			if err := os.WriteFile(path, []byte(dataStr), info.Mode()); err != nil {
				return err
			}
			return nil
		})
	if err != nil {
		panic(err)
	}
}
