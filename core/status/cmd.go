/*
 * Nuts node
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
 */

package status

import (
	"io"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/nuts-foundation/nuts-node/core"
)

// Cmd contains sub-commands for the remote client
func Cmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Shows the status of the Nuts Node.",
		RunE: func(cmd *cobra.Command, args []string) error {
			config := core.NewClientConfigForCommand(cmd)
			targetURL := config.GetAddress() + diagnosticsEndpoint
			response, err := http.Get(targetURL)
			if err != nil {
				return err
			}
			if err = core.TestResponseCode(http.StatusOK, response); err != nil {
				return err
			}
			bytes, _ := io.ReadAll(response.Body)
			cmd.Println(string(bytes))
			return nil
		},
	}
}
