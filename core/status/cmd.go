/*
 * Nuts node
 * Copyright (C) 2021. Nuts community
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
	"fmt"
	"github.com/spf13/cobra"
	"io/ioutil"
	"net/http"

	"github.com/nuts-foundation/nuts-node/core"
)

// Cmd contains sub-commands for the remote client
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Shows the status of the Nuts Node.",
		RunE: func(cmd *cobra.Command, args []string) error {
			config := core.NewClientConfig()
			if err := config.Load(cmd.PersistentFlags()); err != nil {
				return err
			}
			targetURL := config.GetAddress() + diagnosticsEndpoint
			response, err := http.Get(targetURL)
			if err != nil {
				return err
			}
			if response.StatusCode != http.StatusOK {
				return fmt.Errorf("unexpected HTTP response code (url=%s): %d", targetURL, response.StatusCode)
			}
			bytes, _ := ioutil.ReadAll(response.Body)
			cmd.Println(string(bytes))
			return nil
		},
	}
	return cmd
}
