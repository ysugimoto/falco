package ast

import (
	"testing"
)

func TestFunctionCallExpression(t *testing.T) {
	fn := &FunctionCallExpression{
		Meta: New(T, 0, comments("/* This is comment */"), comments("/* This is comment */")),
		Function: &Ident{
			Meta:  New(T, 0),
			Value: "url.pathname",
		},
		Arguments: []Expression{
			&String{
				Meta:  New(T, 0),
				Value: "/foo",
			},
		},
	}

	expect := `/* This is comment */ url.pathname("/foo") /* This is comment */`

	if fn.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, fn.String())
	}
}
