package ast

import (
	"testing"
)

func TestBreakStatement(t *testing.T) {
	brk := &BreakStatement{
		Meta: New(T, 0, comments("// leading comment"), comments("// trailing comment"), comments("/* infix comment */")),
	}

	expect := `// leading comment
break /* infix comment */; // trailing comment
`

	assert(t, brk.String(), expect)
}
