package ast

import (
	"testing"
)

func TestReturnStatement(t *testing.T) {
	r := &ReturnStatement{
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
			Value: "pass",
		},
	}

	expect := `// This is comment
return(pass); // This is comment
`

	if r.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, r.String())
	}
}
