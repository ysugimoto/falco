package ast

import (
	"testing"
)

func TestGotoStatement(t *testing.T) {
	g := &GotoStatement{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
		Destination: &Ident{
			Meta:  New(T, 0),
			Value: "update_and_set",
		},
	}

	expect := `// This is comment
goto update_and_set; // This is comment
`

	if g.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, g.String())
	}
}
