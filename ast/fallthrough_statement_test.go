package ast

import (
	"testing"
)

func TestFallthroughStatement(t *testing.T) {
	ft := &FallthroughStatement{
		Meta: New(T, 0, comments("// leading comment"), comments("// trailing comment"), comments("/* infix comment */")),
	}

	expect := `// leading comment
fallthrough /* infix comment */; // trailing comment
`
	assert(t, ft.String(), expect)
}
