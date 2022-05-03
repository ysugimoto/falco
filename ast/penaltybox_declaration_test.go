package ast

import (
	"testing"
)

func TestPenaltyboxStatement(t *testing.T) {
	p := &PenaltyboxDeclaration{
		Meta: New(T, 0, comments("// This is comment"), comments("/* This is comment */")),
		Name: &Ident{
			Meta:  New(T, 0),
			Value: "ip_pbox",
		},
		Block: &BlockStatement{
			Meta: New(T, 0, comments("/* This is comment */")),
		},
	}

	expect := `// This is comment
penaltybox ip_pbox {
} /* This is comment */
`

	if p.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, p.String())
	}
}
