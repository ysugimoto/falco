package ast

import (
	"testing"
)

func TestImportStatement(t *testing.T) {
	is := &ImportStatement{
		Meta: New(T, 0, comments("// leading comment"), comments("// leading comment")),
		Name: &Ident{
			Meta:  New(T, 0, comments("/* before_name */"), comments("/* after_name */")),
			Value: "boltsort",
		},
	}

	expect := `// leading comment
import /* before_name */ boltsort /* after_name */; // leading comment
`

	assert(t, is.String(), expect)
}
