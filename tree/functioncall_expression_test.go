package ast

import (
	"testing"
)

func TestFunctionCallExpression(t *testing.T) {
	fn := &FunctionCallExpression{
		Meta: &Meta{
			Leading: []*Comment{
				{
					Value: "/* This is comment */",
				},
			},
			Trailing: []*Comment{
				{
					Value: "/* This is comment */",
				},
			},
		},
		Function: &Ident{
			Value: "url.pathname",
		},
		Arguments: []Expression{
			&String{
				Value: "/foo",
			},
		},
	}

	expect := `/* This is comment */ url.pathname("/foo") /* This is comment */`

	if fn.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, fn.String())
	}
}
