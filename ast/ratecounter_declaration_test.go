package ast

import (
	"testing"
)

func TestRatecounterStatement(t *testing.T) {
	r := &RatecounterDeclaration{
		Meta: New(T, 0, comments("// This is comment"), comments("/* This is comment */")),
		Name: &Ident{
			Meta:  New(T, 0),
			Value: "requests_rate",
		},
		Block: &BlockStatement{
			Meta: New(T, 0, comments("/* This is comment */")),
		},
	}

	expect := `// This is comment
ratecounter requests_rate {
} /* This is comment */
`

	if r.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, r.String())
	}
}
