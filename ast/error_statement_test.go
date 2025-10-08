package ast

import (
	"testing"
)

func TestErrorStatement(t *testing.T) {
	e := &ErrorStatement{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
		Code: &Ident{
			Meta:  New(T, 0, comments("/* before_code */")),
			Value: "200",
		},
		Argument: &String{
			Meta:  New(T, 0, comments("/* before_argument */"), comments("/* after_argument */")),
			Value: "/foobar",
		},
	}

	expect := `// This is comment
error /* before_code */ 200 /* before_argument */ "/foobar" /* after_argument */; // This is comment
`
	assert(t, e.String(), expect)
}
