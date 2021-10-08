package dag

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDotGraphVisitor(t *testing.T) {
	doTest := func(style LabelStyle) {
		t.Run(fmt.Sprintf("%d", style), func(t *testing.T) {
			visitor := NewDotGraphVisitor(style)
			txA, _, _ := CreateTestTransaction(1)
			txB, _, _ := CreateTestTransaction(2, txA.Ref())
			txC, _, _ := CreateTestTransaction(3, txA.Ref())
			visitor.Accept(nil, txA)
			visitor.Accept(nil, txB)
			visitor.Accept(nil, txC)
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
