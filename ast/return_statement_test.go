package ast

import (
	"testing"
)

func TestReturnStatement(t *testing.T) {
	t.Run("Without parenthesis", func(t *testing.T) {
		r := &ReturnStatement{
			Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
			ReturnExpression: &Ident{
				Meta:  New(T, 0, comments("/* before_state */"), comments("/* after_state */")),
				Value: "pass",
			},
		}

		expect := `// This is comment
return /* before_state */ pass /* after_state */; // This is comment
`

		assert(t, r.String(), expect)
	})

	t.Run("With parenthesis", func(t *testing.T) {
		r := &ReturnStatement{
			Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
			ReturnExpression: &Ident{
				Meta:  New(T, 0, comments("/* before_state */"), comments("/* after_state */")),
				Value: "pass",
			},
			HasParenthesis:              true,
			ParenthesisLeadingComments:  comments("/* before_paren */"),
			ParenthesisTrailingComments: comments("/* after_paren */"),
		}

		expect := `// This is comment
return /* before_paren */ (/* before_state */ pass /* after_state */) /* after_paren */; // This is comment
`

		assert(t, r.String(), expect)
	})
}
