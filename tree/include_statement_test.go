package ast

import (
	"testing"
)

func testingncludeStatement(t *testing.T) {
	is := &IncludeStatement{
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
		Module: &String{
			Value: "mod_recv",
		},
	}

	expect := `// This is comment
include "mod_recv"; // This is comment
`

	if is.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, is.String())
	}
}
