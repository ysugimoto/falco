package ast

import (
	"testing"
)

func TestEsiStatement(t *testing.T) {
	esi := &EsiStatement{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
	}

	expect := `// This is comment
esi; // This is comment
`

	if esi.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, esi.String())
	}
}
