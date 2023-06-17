/*
 * Copyright (C) 2023 Nuts community
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

package browser

import (
	"context"
	"github.com/chromedp/chromedp"
)

func NewChrome(headless bool) (context.Context, context.CancelFunc) {
	var execCtx context.Context
	var execCtxCancel context.CancelFunc
	if headless {
		execCtx, execCtxCancel = chromedp.NewRemoteAllocator(context.Background(), "http://localhost:9222")
	} else {
		execCtx, execCtxCancel = chromedp.NewExecAllocator(context.Background(), append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", false))...)
	}

	ctx, cancel := chromedp.NewContext(
		execCtx,
		//chromedp.WithDebugf(log.Printf),
	)
	go func() {
		<-ctx.Done()
		execCtxCancel()
	}()

	return ctx, cancel
}
