package ast

import (
	"testing"
)

func TestFunctionCallStatement(t *testing.T) {
	fn := &FunctionCallStatement{
		Meta: New(T, 0, comments("/* leading comment */"), comments("/* trailing comment */"), comments("/* infix comment */")),
		Function: &Ident{
			Meta:  New(T, 0),
			Value: "std.collect",
		},
		Arguments: []Expression{
			&String{
				Meta:  New(T, 0, comments("/* before_arg1 */"), comments("/* after_arg1 */")),
				Value: "req.http.Cookie",
			},
			&String{
				Meta:  New(T, 0, comments("/* before_arg2 */"), comments("/* after_arg2 */")),
				Value: ";",
			},
		},
	}

	expect := `/* leading comment */
std.collect(/* before_arg1 */ "req.http.Cookie" /* after_arg1 */, /* before_arg2 */ ";" /* after_arg2 */) /* infix comment */; /* trailing comment */`

	assert(t, fn.String(), expect)
}
