package ast

import (
	"testing"
)

func TestAddStatement(t *testing.T) {
	add := &AddStatement{
		Meta: New(T, 0, WithComments(CommentsMap{
			PlaceLeading:  comments("// This is comment"),
			PlaceTrailing: comments("// This is comment"),
		})),
		Ident: &Ident{
			Meta:  New(T, 0),
			Value: "req.http.Host",
		},
		Operator: &Operator{
			Operator: "=",
		},
		Value: &String{
			Meta:  New(T, 0),
			Value: "example.com",
		},
	}

	expect := `// This is comment
add req.http.Host = "example.com"; // This is comment
`

	if add.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, add.String())
	}
}
