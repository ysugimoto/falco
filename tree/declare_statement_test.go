package ast

import (
	"testing"
)

func TestDeclareStatement(t *testing.T) {
	declare := &DeclareStatement{
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
		Name: &Ident{
			Value: "var.Foo",
		},
		ValueType: &Ident{
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
