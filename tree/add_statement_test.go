package ast

import (
	"testing"
)

func TestAddStatement(t *testing.T) {
	add := &AddStatement{
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
			Value: "req.http.Host",
		},
		Operator: &Operator{
			Operator: "=",
		},
		Value: &String{
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
