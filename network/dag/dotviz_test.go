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

package dag

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDotGraphVisitor(t *testing.T) {
	doTest := func(style LabelStyle) {
		t.Run(fmt.Sprintf("%d", style), func(t *testing.T) {
			visitor := NewDotGraphVisitor(style)
			txA, _, _ := CreateTestTransaction(1)
			txB, _, _ := CreateTestTransaction(2, txA)
			txC, _, _ := CreateTestTransaction(3, txA)
			visitor.Accept(txA)
			visitor.Accept(txB)
			visitor.Accept(txC)
			actual := visitor.Render()
			// Since visualization changes now and then and the TX references differ every time the test is run, just do some sanity checks
			assert.Contains(t, actual, "digraph {")
			assert.Contains(t, actual, "}")
			assert.Contains(t, actual, txA.Ref().String())
			assert.Contains(t, actual, txB.Ref().String())
			assert.Contains(t, actual, txC.Ref().String())
			assert.Contains(t, actual, "->")
		})
	}
	doTest(ShowShortRefLabelStyle)
	doTest(ShowRefLabelStyle)
	doTest(ShowAliasLabelStyle)
}
