package ast

import (
	"testing"
)

func TestDeclareStatement(t *testing.T) {
	declare := &DeclareStatement{
		Meta: New(T, 0, WithComments(CommentsMap{
			PlaceLeading:  comments("// This is comment"),
			PlaceTrailing: comments("// This is comment"),
		})),
		Name: &Ident{
			Meta:  New(T, 0),
			Value: "var.Foo",
		},
		ValueType: &Ident{
			Meta:  New(T, 0),
			Value: "STRING",
		},
	}

	expect := `// This is comment
declare local var.Foo STRING; // This is comment
`

	if declare.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, declare.String())
	}
}
