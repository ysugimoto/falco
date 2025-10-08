package ast

import (
	"testing"
)

func TestFunctionCallExpression(t *testing.T) {
	fn := &FunctionCallExpression{
		Meta: New(T, 0, comments("/* leading */"), comments("/* trailing */")),
		Function: &Ident{
			Meta:  New(T, 0),
			Value: "url.pathname",
		},
		Arguments: []Expression{
			&String{
				Meta:  New(T, 0, comments("/* before_arg */"), comments("/* after_arg */")),
				Value: "/foo",
			},
		},
	}

	expect := `/* leading */ url.pathname(/* before_arg */ "/foo" /* after_arg */) /* trailing */`
	assert(t, fn.String(), expect)
}
