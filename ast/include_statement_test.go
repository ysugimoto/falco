package ast

import (
	"testing"
)

func TestIncludeStatement(t *testing.T) {
	is := &IncludeStatement{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
		Module: &String{
			Meta:  New(T, 0),
			Value: "mod_recv",
		},
	}

	expect := `// This is comment
include "mod_recv"; // This is comment
`

	if is.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, is.String())
	}
}
