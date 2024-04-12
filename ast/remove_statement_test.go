package ast

import (
	"testing"
)

func TestRemoveStatement(t *testing.T) {
	remove := &RemoveStatement{
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
remove req.http.Foo; // This is comment
`

	if remove.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, remove.String())
	}
}
