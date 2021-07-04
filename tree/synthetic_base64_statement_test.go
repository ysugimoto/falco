package ast

import (
	"testing"
)

func TestSynthericBase64Statement(t *testing.T) {
	s := &SyntheticBase64Statement{
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
synthetic.base64 "foobar"; // This is comment
`

	if s.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, s.String())
	}
}
