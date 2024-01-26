package ast

import (
	"testing"
)

func TestFallthroughStatement(t *testing.T) {
	ft := &FallthroughStatement{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
	}

	expect := `// This is comment
fallthrough; // This is comment
`

	if ft.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, ft.String())
	}
}
