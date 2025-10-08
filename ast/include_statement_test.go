package ast

import (
	"testing"
)

func TestIncludeStatement(t *testing.T) {
	is := &IncludeStatement{
		Meta: New(T, 0, comments("// leading comment"), comments("// trailing comment")),
		Module: &String{
			Meta:  New(T, 0, comments("/* before_name */"), comments("/* after_name */")),
			Value: "mod_recv",
		},
	}

	expect := `// leading comment
include /* before_name */ "mod_recv" /* after_name */; // trailing comment
`
	assert(t, is.String(), expect)
}
