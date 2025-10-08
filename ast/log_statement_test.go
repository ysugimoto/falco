package ast

import (
	"testing"
)

func TestLogStatement(t *testing.T) {
	log := &LogStatement{
		Meta: New(T, 0, comments("// leading comment"), comments("// trailing comment")),
		Value: &String{
			Meta:  New(T, 0, comments("/* before_name */"), comments("/* after_name */")),
			Value: "foobar",
		},
	}

	expect := `// leading comment
log /* before_name */ "foobar" /* after_name */; // trailing comment
`
	assert(t, log.String(), expect)
}
