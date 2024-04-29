package ast

import (
	"testing"
)

func TestSubroutineStatement(t *testing.T) {
	sub := &SubroutineDeclaration{
		Meta: New(T, 0, comments("// leading comment"), comments("/* trailing comment */")),
		Name: &Ident{
			Meta:  New(T, 0, comments("/* before_name */"), comments("/* after_name */")),
			Value: "vcl_recv",
		},
		Block: &BlockStatement{
			Meta: New(T, 1, comments(), comments(), comments("// infix comment")),
			Statements: []Statement{
				&EsiStatement{
					Meta: New(T, 1, comments("// This is comment"), comments("/* This is comment */")),
				},
			},
		},
	}

	expect := `// leading comment
sub /* before_name */ vcl_recv /* after_name */ {
  // This is comment
  esi; /* This is comment */
  // infix comment
} /* trailing comment */
`

	assert(t, sub.String(), expect)
}
