package ast

import (
	"testing"
)

func TestCallStatement(t *testing.T) {
	call := &CallStatement{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
		Subroutine: &Ident{
			Meta:  New(T, 0),
			Value: "mod_recv",
		},
	}

	expect := `// This is comment
call mod_recv; // This is comment
`

	if call.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, call.String())
	}
}
