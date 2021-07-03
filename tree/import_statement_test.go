package ast

import (
	"testing"
)

func TestImportStatement(t *testing.T) {
	is := &ImportStatement{
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
