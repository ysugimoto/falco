package ast

import (
	"testing"
)

func TestSynthericStatement(t *testing.T) {
	s := &SyntheticStatement{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
		Value: &String{
			Meta:  New(T, 0),
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
