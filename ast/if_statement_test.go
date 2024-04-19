package ast

import (
	"testing"
)

func TestIfStatement(t *testing.T) {
	ifs := &IfStatement{
		Meta:    New(T, 0, comments("// This is comment"), comments("/* This is comment */"), comments("/* infix */")),
		Keyword: "if",
		Condition: &Ident{
			Meta:  New(T, 0, comments("/* before_condition */"), comments("/* after_condition */")),
			Value: "req.http.Host",
		},
		Another: []*IfStatement{
			{
				Meta:    New(T, 0, comments("// This is comment"), comments("/* This is comment */"), comments("/* infix */")),
				Keyword: "else if",
				Condition: &Ident{
					Meta:  New(T, 0, comments("/* before_condition */"), comments("/* after_condition */")),
					Value: "req.http.Host",
				},
				Consequence: &BlockStatement{
					Meta: New(T, 0, comments("/* before_block */"), comments("/* This is comment */")),
					Statements: []Statement{
						&EsiStatement{
							Meta: New(T, 1, comments("// This is comment"), comments("/* This is comment */")),
						},
					},
				},
			},
		},
		Consequence: &BlockStatement{
			Meta: New(T, 0, comments("/* before_block */")),
			Statements: []Statement{
				&EsiStatement{
					Meta: New(T, 1, comments("// This is comment"), comments("/* This is comment */")),
				},
			},
		},
		Alternative: &ElseStatement{
			Meta: New(T, 0, comments("// This is comment"), comments("/* This is comment */"), comments("/* infix */")),
			Consequence: &BlockStatement{
				Meta: New(T, 0),
				Statements: []Statement{
					&EsiStatement{
						Meta: New(T, 1, comments("// This is comment"), comments("/* This is comment */")),
					},
				},
			},
		},
	}

	expect := `// This is comment
if /* infix */ (/* before_condition */ req.http.Host /* after_condition */) /* before_block */ {
  // This is comment
  esi; /* This is comment */
}
// This is comment
else if /* infix */ (/* before_condition */ req.http.Host /* after_condition */) /* before_block */ {
  // This is comment
  esi; /* This is comment */
} /* This is comment */
// This is comment
else /* infix */ {
  // This is comment
  esi; /* This is comment */
} /* This is comment */
`

	assert(t, ifs.String(), expect)
}
