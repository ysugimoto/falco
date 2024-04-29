package ast

import (
	"testing"
)

func TestCallStatement(t *testing.T) {
	call := &CallStatement{
		Meta: New(T, 0, comments("// leading comment"), comments("// trailing comment")),
		Subroutine: &Ident{
			Meta:  New(T, 0, comments("/* before_subroutine */"), comments("/* after_subroutine */")),
			Value: "mod_recv",
		},
	}

	expect := `// leading comment
call /* before_subroutine */ mod_recv /* after_subroutine */; // trailing comment
`

	assert(t, call.String(), expect)
}
