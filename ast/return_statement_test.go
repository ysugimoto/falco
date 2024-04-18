package ast

import (
	"testing"
)

func TestReturnStatement(t *testing.T) {
	t.Run("Without parenthesis", func(t *testing.T) {
		r := &ReturnStatement{
			Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
			ReturnExpression: &Ident{
				Meta:  New(T, 0),
				Value: "pass",
			},
		}

		expect := `// This is comment
return pass; // This is comment
`

		if r.String() != expect {
			t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, r.String())
		}
	})

	t.Run("With parenthesis", func(t *testing.T) {
		r := &ReturnStatement{
			Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
			ReturnExpression: &Ident{
				Meta:  New(T, 0),
				Value: "pass",
			},
			HasParenthesis: true,
		}

		expect := `// This is comment
return (pass); // This is comment
`

		if r.String() != expect {
			t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, r.String())
		}
	})
}
