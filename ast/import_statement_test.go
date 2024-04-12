package ast

import (
	"testing"
)

func TestImportStatement(t *testing.T) {
	is := &ImportStatement{
		Meta: New(T, 0, WithComments(CommentsMap{
			PlaceLeading:  comments("// This is comment"),
			PlaceTrailing: comments("// This is comment"),
		})),
		Name: &Ident{
			Meta:  New(T, 0),
			Value: "boltsort",
		},
	}

	expect := `// This is comment
import boltsort; // This is comment
`

	if is.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, is.String())
	}
}
