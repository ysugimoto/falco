package ast

import (
	"testing"
)

func TestRatecounterStatement(t *testing.T) {
	r := &RatecounterDeclaration{
		Meta: New(T, 0, comments("// This is comment"), comments("/* This is comment */")),
		Name: &Ident{
			Meta:  New(T, 0, comments("/* before_name */"), comments("/* after_name */")),
			Value: "requests_rate",
		},
		Block: &BlockStatement{
			Meta: New(T, 0, comments(), comments("/* This is comment */")),
		},
	}

	expect := `// This is comment
ratecounter /* before_name */ requests_rate /* after_name */ {
} /* This is comment */
`

	assert(t, r.String(), expect)
}
