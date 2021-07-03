package ast

import (
	"testing"
)

func TestRestartStatement(t *testing.T) {
	restart := &RestartStatement{
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
	}

	expect := `// This is comment
restart; // This is comment
`

	if restart.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, restart.String())
	}
}
