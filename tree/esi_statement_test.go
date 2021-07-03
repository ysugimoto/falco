package ast

import (
	"testing"
)

func TestEsiStatement(t *testing.T) {
	esi := &EsiStatement{
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
	}

	expect := `// This is comment
esi; // This is comment
`

	if esi.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, esi.String())
	}
}
