package ast

import (
	"testing"
)

func TestCallStatement(t *testing.T) {
	call := &CallStatement{
		Meta: &Meta{
			Leading: []*Comment{
				{
					Value: "// This is comment",
				},
			},
			Trailing: []*Comment{
				{
					Value: "// This is comment",
				},
			},
		},
		Subroutine: &Ident{
			Value: "mod_recv",
		},
	}

	expect := `// This is comment
call mod_recv; // This is comment
`

	if call.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, call.String())
	}
}
