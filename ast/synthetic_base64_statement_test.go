package ast

import (
	"testing"
)

func TestSyntheticBase64Statement(t *testing.T) {
	s := &SyntheticBase64Statement{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
		Value: &String{
			Meta:  New(T, 0, comments("/* before_expr */"), comments("/* after_expr */")),
			Value: "foobar",
		},
	}

	expect := `// This is comment
synthetic.base64 /* before_expr */ "foobar" /* after_expr */; // This is comment
`

	assert(t, s.String(), expect)
}
