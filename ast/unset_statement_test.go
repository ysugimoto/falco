package ast

import (
	"testing"
)

func TestUnsetStatement(t *testing.T) {
	unset := &UnsetStatement{
		Meta: New(T, 0, WithComments(CommentsMap{
			PlaceLeading:  comments("// This is comment"),
			PlaceTrailing: comments("// This is comment"),
		})),
		Ident: &Ident{
			Meta:  New(T, 0),
			Value: "req.http.Foo",
		},
	}

	expect := `// This is comment
unset req.http.Foo; // This is comment
`

	if unset.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, unset.String())
	}
}
