package ast

import (
	"testing"
)

func TestUnsetStatement(t *testing.T) {
	unset := &UnsetStatement{
		Meta: New(T, 0, comments("// This is comment"), comments("// This is comment")),
		Ident: &Ident{
			Meta:  New(T, 0, comments("/* before_name */"), comments("/* after_name */")),
			Value: "req.http.Foo",
		},
	}

	expect := `// This is comment
unset /* before_name */ req.http.Foo /* after_name */; // This is comment
`

	assert(t, unset.String(), expect)
}
