package ast

import (
	"testing"
)

func TestUnsetStatement(t *testing.T) {
	unset := &UnsetStatement{
		Meta: &Meta{
			Leading: []*Comment{
				{
					Value: "// This is comment",
				},
			},
			Trailing: []*Comment{
				{
					Value: "// This is comment",
				},
			},
		},
		Ident: &Ident{
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
