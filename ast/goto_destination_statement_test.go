package ast

import (
	"testing"
)

func TestGotoDestinationStatement(t *testing.T) {
	g := &GotoDestinationStatement{
		Meta: New(T, 0, WithComments(CommentsMap{
			PlaceLeading:  comments("// This is comment"),
			PlaceTrailing: comments("// This is comment"),
		})),
		Name: &Ident{
			Meta:  New(T, 0),
			Value: "update_and_set:",
		},
	}

	expect := `// This is comment
update_and_set: // This is comment
`

	if g.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, g.String())
	}
}
