package ast

import (
	"testing"
)

func TestSubroutineStatement(t *testing.T) {
	sub := &SubroutineDeclaration{
		Meta: New(T, 0, comments("// This is comment"), comments("/* This is comment */")),
		Name: &Ident{
			Meta:  New(T, 0),
			Value: "vcl_recv",
		},
		Block: &BlockStatement{
			Meta: New(T, 0, comments("// This is comment"), comments("/* This is comment */")),
			Statements: []Statement{
				&EsiStatement{
					Meta: New(T, 1, comments("// This is comment"), comments("/* This is comment */")),
				},
			},
		},
	}

	expect := `// This is comment
sub vcl_recv {
  // This is comment
  esi; /* This is comment */
} /* This is comment */
`

	if sub.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, sub.String())
	}
}
