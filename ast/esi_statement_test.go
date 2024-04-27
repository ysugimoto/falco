package ast

import (
	"testing"
)

func TestEsiStatement(t *testing.T) {
	esi := &EsiStatement{
		Meta: New(T, 0, comments("// leading comment"), comments("// trailing comment"), comments("/* infix comment */")),
	}

	expect := `// leading comment
esi /* infix comment */; // trailing comment
`
	assert(t, esi.String(), expect)
}
