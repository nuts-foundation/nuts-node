/*
 * Copyright (C) 2022 Nuts community
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

package test

import (
	"fmt"
	"path"
)

func GetIntegrationTestConfig(testDirectory string) map[string]string {
	httpAddress := fmt.Sprintf("localhost:%d", FreeTCPPort())
	return map[string]string{
		"configfile":              path.Join(testDirectory, "nuts.yaml"), // does not exist, but that's okay: default config
		"datadir":                 testDirectory,
		"network.enabletls":       "false",
		"network.grpcaddr":        fmt.Sprintf("localhost:%d", FreeTCPPort()),
		"auth.contractvalidators": "dummy", // disables IRMA
		"http.default.address":    httpAddress,
		"events.nats.port":        fmt.Sprintf("%d", FreeTCPPort()),
	}
}
