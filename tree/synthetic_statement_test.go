package ast

import (
	"testing"
)

func TestSynthericStatement(t *testing.T) {
	s := &SyntheticStatement{
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
		Value: &String{
			Value: "foobar",
		},
	}

	expect := `// This is comment
synthetic "foobar"; // This is comment
`

	if s.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, s.String())
	}
}
