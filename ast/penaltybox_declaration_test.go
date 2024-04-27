package ast

import (
	"testing"
)

func TestPenaltyboxStatement(t *testing.T) {
	p := &PenaltyboxDeclaration{
		Meta: New(T, 0, comments("// This is comment"), comments("/* This is comment */")),
		Name: &Ident{
			Meta:  New(T, 0, comments("/* before_name */"), comments("/* after_name */")),
			Value: "ip_pbox",
		},
		Block: &BlockStatement{
			Meta: New(T, 0, comments(), comments("/* This is comment */")),
		},
	}

	expect := `// This is comment
penaltybox /* before_name */ ip_pbox /* after_name */ {
} /* This is comment */
`
	assert(t, p.String(), expect)
}
