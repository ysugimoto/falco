package ast

import (
	"testing"
)

func TestSetStatement(t *testing.T) {
	set := &SetStatement{
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
set req.http.Host = "example.com"; // This is comment
`

	if set.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, set.String())
	}
}
