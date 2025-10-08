package ast

import (
	"testing"
)

func TestGotoDestinationStatement(t *testing.T) {
	g := &GotoDestinationStatement{
		Meta: New(T, 0, comments("// leading comment"), comments("// trailing comment")),
		Name: &Ident{
			Meta:  New(T, 0),
			Value: "update_and_set:",
		},
	}

	expect := `// leading comment
update_and_set: // trailing comment
`
	assert(t, g.String(), expect)
}
