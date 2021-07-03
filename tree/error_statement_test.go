package ast

import (
	"testing"
)

func TestErrorStatement(t *testing.T) {
	e := &ErrorStatement{
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
		Code: &Ident{
			Value: "200",
		},
		Argument: &String{
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
