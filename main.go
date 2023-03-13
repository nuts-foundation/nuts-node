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
 *
 */

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/nuts-foundation/nuts-node/cmd"
	"github.com/sirupsen/logrus"
)

func main() {
	// Listen for interrupt signals (CTRL/CMD+C, OS instructing the process to stop) to cancel context.
	ctx, cancelNotify := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelNotify()

	err := cmd.Execute(ctx, cmd.CreateSystem(cancelNotify))
	if err != nil {
		logrus.Error(err)
	}
}
