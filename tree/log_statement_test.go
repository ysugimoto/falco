package ast

import (
	"testing"
)

func TestLogStatement(t *testing.T) {
	log := &LogStatement{
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
		Value: &String{
			Value: "foobar",
		},
	}

	expect := `// This is comment
log "foobar"; // This is comment
`

	if log.String() != expect {
		t.Errorf("stringer error.\nexpect:\n%s\nactual:\n%s\n", expect, log.String())
	}
}
