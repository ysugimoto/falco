package ast

import (
	"testing"
)

func TestIfStatement(t *testing.T) {
	ifs := &IfStatement{
		Meta: New(T, 0, comments("// This is comment"), comments("/* This is comment */")),
		Condition: &Ident{
			Meta:  New(T, 0),
			Value: "req.http.Host",
		},
		Another: []*IfStatement{
			{
				Meta: New(T, 0, comments("// This is comment"), comments("/* This is comment */")),
				Condition: &Ident{
					Meta:  New(T, 0),
					Value: "req.http.Host",
				},
				Consequence: &BlockStatement{
					Meta: New(T, 0, comments("// This is comment"), comments("/* This is comment */")),
					Statements: []Statement{
						&EsiStatement{
							Meta: New(T, 1, comments("// This is comment"), comments("/* This is comment */")),
						},
					},
				},
			},
		},
		Consequence: &BlockStatement{
			Meta: New(T, 0, comments("// This is comment"), comments("/* This is comment */")),
			Statements: []Statement{
				&EsiStatement{
					Meta: New(T, 1, comments("// This is comment"), comments("/* This is comment */")),
				},
			},
		},
		Alternative: &ElseStatement{
			Meta: New(T, 0, comments("// This is comment"), comments("/* This is comment */")),
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
if (req.http.Host) {
  // This is comment
  esi; /* This is comment */
}
// This is comment
else if (req.http.Host) {
  // This is comment
  esi; /* This is comment */
} /* This is comment */
// This is comment
else {
  // This is comment
  esi; /* This is comment */
} /* This is comment */
`

	if ifs.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, ifs.String())
	}
}
