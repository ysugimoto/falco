package ast

import (
	"testing"
)

func TestSynthericBase64Statement(t *testing.T) {
	s := &SyntheticBase64Statement{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
		Value: &String{
			Meta:  New(T, 0),
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
