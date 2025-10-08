package ast

import (
	"testing"
)

func TestBlockStatement(t *testing.T) {
	block := &BlockStatement{
		Meta: New(T, 1, comments(), comments(), comments("// This is infix comment")),
		Statements: []Statement{
			&SetStatement{
				Meta: New(T, 1, comments("// This is comment"), comments("// This is comment")),
				Ident: &Ident{
					Meta:  New(T, 0),
					Value: "req.http.Host",
				},
				Operator: &Operator{
					Operator: "=",
				},
				Value: &String{
					Meta:  New(T, 0),
					Value: "example.com",
				},
			},
		},
	}

	expect := `{
  // This is comment
  set req.http.Host = "example.com"; // This is comment
  // This is infix comment
}`

	assert(t, block.String(), expect)
}
