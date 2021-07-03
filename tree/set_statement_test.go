package ast

import (
	"testing"
)

func TestSetStatement(t *testing.T) {
	set := &SetStatement{
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
set req.http.Host = "example.com"; // This is comment
`

	if set.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, set.String())
	}
}
