package ast

import (
	"testing"
)

func TestErrorStatement(t *testing.T) {
	e := &ErrorStatement{
		Meta: New(T, 0, WithComments(CommentsMap{
			PlaceLeading:  comments("// This is comment"),
			PlaceTrailing: comments("// This is comment"),
		})),
		Code: &Ident{
			Meta:  New(T, 0),
			Value: "200",
		},
		Argument: &String{
			Meta:  New(T, 0),
			Value: "/foobar",
		},
	}

	expect := `// This is comment
error 200 "/foobar"; // This is comment
`

	if e.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, e.String())
	}
}
